#!/usr/bin/env python3
"""Audit, build, leak-inspect, and offline-verify Python + JS web applications.

Bundled helper CLI for the `protect-offline-python-webapp` skill.
Uses Python stdlib plus project/environment tools (Nuitka, Cython, cryptography)
without shell string interpolation or unscoped file deletions.
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import importlib.machinery
import json
import math
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_UNVERIFIED = "UNVERIFIED"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

WINDOWS_REPARSE_ATTR = 0x400

SECRET_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("PEM_PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |)?PRIVATE KEY-----")),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GENERIC_SECRET_ASSIGN", re.compile(r"(?i)\b(?:api_key|secret_key|private_key|auth_token|client_secret)\s*[:=]\s*['\"][^'\"]{12,}['\"]")),
    ("SYNTHETIC_TEST_SECRET", re.compile(r"SYNTHETIC_TEST_SECRET_[A-Za-z0-9_-]{6,}")),
]

DYNAMIC_HAZARD_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("dynamic_importlib", re.compile(r"\bimportlib\.import_module\s*\(")),
    ("dunder_import", re.compile(r"\b__import__\s*\(")),
    ("pkgutil_discovery", re.compile(r"\bpkgutil\.(?:iter_modules|walk_packages)\s*\(")),
    ("eval_or_exec", re.compile(r"\b(?:eval|exec)\s*\(")),
    ("pickle_usage", re.compile(r"\bpickle\.(?:load|loads|dump|dumps)\s*\(")),
    ("file_relative_asset", re.compile(r"__file__")),
]

EXTERNAL_URL_RE = re.compile(
    r"""(?ix)
    (?:
        (?:https?|wss?)://([A-Za-z0-9.-]+)(?::\d+)?(?:/[^\s"'<>)]*)?
      | (?:src|href)\s*=\s*['"]//([A-Za-z0-9.-]+)(?::\d+)?/[^\s"'<>]*['"]
    )
    """
)

SOURCEMAP_DIRECTIVE_RE = re.compile(r"(?m)(?://[#@]\s*sourceMappingURL=|/\*[#@]\s*sourceMappingURL=)\S+")
HTML_SOURCE_COMMENT_RE = re.compile(r"<!--[\s\S]*?(?:\bdef\s+\w+\s*\(|\bfunction\s+\w+\s*\(|Traceback \(most recent call last\)|DO_NOT_SHIP)[\s\S]*?-->")

OPAQUE_CONTAINER_EXTS = {".exe", ".pyz", ".pkg", ".msi", ".dmg", ".7z", ".rar", ".asar"}
NESTED_ARCHIVE_EXTS = (".zip", ".whl", ".tar.gz", ".tgz", ".tar")


class ToolError(RuntimeError):
    """Raised on validation or operational errors that must exit non-zero."""


def is_reparse_or_symlink(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        st = os.lstat(path)
        file_attrs = getattr(st, "st_file_attributes", 0)
        return bool(file_attrs & WINDOWS_REPARSE_ATTR)
    except OSError:
        return False


def ensure_within_scope(target: Path, allowed_root: Path, label: str = "path") -> Path:
    resolved_root = allowed_root.resolve()
    resolved_target = target.resolve()
    try:
        resolved_target.relative_to(resolved_root)
    except ValueError as exc:
        raise ToolError(f"Refusing {label} outside allowed scope '{resolved_root}': '{resolved_target}'") from exc
    return resolved_target


def safe_rmtree(target: Path, allowed_root: Path, dry_run: bool = False) -> list[str]:
    """Delete a directory tree safely without following symlinks/junctions outside allowed_root."""
    ensure_within_scope(target, allowed_root, label="cleanup target")
    if target.resolve() == allowed_root.resolve():
        raise ToolError(f"Refusing to delete allowed_root itself: '{allowed_root}'")
    if not target.exists() and not is_reparse_or_symlink(target):
        return []

    planned: list[str] = []

    def _walk_delete(current: Path) -> None:
        if is_reparse_or_symlink(current):
            raise ToolError(f"Refusing to traverse symlink or reparse point during cleanup: '{current}'")
        ensure_within_scope(current, allowed_root, label="cleanup entry")
        if current.is_dir():
            for child in sorted(current.iterdir()):
                _walk_delete(child)
            planned.append(str(current))
            if not dry_run:
                os.chmod(current, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
                current.rmdir()
        else:
            planned.append(str(current))
            if not dry_run:
                os.chmod(current, stat.S_IWRITE | stat.S_IREAD)
                current.unlink()

    _walk_delete(target)
    return planned


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def redact_text(text: str) -> str:
    out = text
    for rule_id, pattern in SECRET_RULES:
        out = pattern.sub(f"<REDACTED:{rule_id}>", out)
    return out


def summarize_overall_status(checks: list[dict[str, Any]]) -> str:
    statuses = {c["status"] for c in checks}
    if STATUS_FAIL in statuses:
        return STATUS_FAIL
    if STATUS_UNVERIFIED in statuses:
        return STATUS_UNVERIFIED
    if STATUS_PASS in statuses:
        return STATUS_PASS
    return STATUS_NOT_APPLICABLE


def load_manifest(manifest_path: Path) -> dict[str, Any]:
    if not manifest_path.is_file():
        raise ToolError(f"Manifest file does not exist: '{manifest_path}'")
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolError(f"Failed to parse manifest JSON '{manifest_path}': {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ToolError("Manifest must be a JSON object with 'schema_version': 1.")
    protected = data.get("protected_modules")
    if not isinstance(protected, list) or not protected:
        raise ToolError("Manifest 'protected_modules' must be a non-empty list.")
    for item in protected:
        if not isinstance(item, dict) or not item.get("module") or not item.get("source"):
            raise ToolError("Each protected_modules item requires 'module' and 'source'.")
    return data


def _extract_external_hosts(content: str, allowed_hosts: set[str]) -> list[str]:
    bad_hosts: list[str] = []
    for match in EXTERNAL_URL_RE.finditer(content):
        host = (match.group(1) or match.group(2) or "").strip().lower()
        if host and host not in allowed_hosts:
            bad_hosts.append(host)
    return sorted(set(bad_hosts))


def cmd_audit(args: argparse.Namespace) -> int:
    project_root = Path(args.project_root).resolve()
    if not project_root.is_dir():
        raise ToolError(f"Project root is not a directory: '{project_root}'")

    if args.output:
        out_path = Path(args.output).resolve()
        try:
            out_path.relative_to(project_root)
            raise ToolError(
                "Audit mode is strictly read-only inside --project-root; write --output outside the project directory."
            )
        except ValueError:
            pass

    skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", ".svelte-kit", "dist", "build"}
    py_files: list[str] = []
    web_files: list[str] = []
    data_candidates: list[str] = []
    dynamic_hazards: list[dict[str, Any]] = []
    external_url_hits: list[dict[str, Any]] = []
    secret_hits: list[dict[str, Any]] = []
    sourcemap_configs: list[str] = []
    packaging_signals: list[str] = []
    uninspected_scopes: list[str] = []

    allowed_hosts = {h.lower() for h in (args.allow_host or ["127.0.0.1", "localhost", "::1"])}

    for root_str, dirs, files in os.walk(project_root, topdown=True, followlinks=False):
        curr_root = Path(root_str)
        kept_dirs: list[str] = []
        for d in dirs:
            d_path = curr_root / d
            if d in skip_dirs:
                uninspected_scopes.append(f"{d_path.relative_to(project_root).as_posix()}/ (skipped directory)")
                continue
            if is_reparse_or_symlink(d_path):
                uninspected_scopes.append(f"{d_path.relative_to(project_root).as_posix()} (symlink/reparse skipped)")
                continue
            kept_dirs.append(d)
        dirs[:] = kept_dirs

        for fname in sorted(files):
            fpath = curr_root / fname
            if is_reparse_or_symlink(fpath):
                uninspected_scopes.append(f"{fpath.relative_to(project_root).as_posix()} (symlink skipped)")
                continue
            rel = fpath.relative_to(project_root).as_posix()
            suffix = fpath.suffix.lower()

            if fname in {"pyproject.toml", "setup.py", "Dockerfile", "package.json"} or suffix == ".spec":
                packaging_signals.append(rel)
            if suffix in {".exe", ".pyz", ".whl", ".zip", ".onnx", ".pt", ".safetensors", ".sqlite", ".db"}:
                data_candidates.append(rel)

            if suffix == ".py":
                py_files.append(rel)
                try:
                    text = fpath.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    uninspected_scopes.append(f"{rel} (unreadable)")
                    continue
                for hazard_id, pattern in DYNAMIC_HAZARD_PATTERNS:
                    for line_no, line in enumerate(text.splitlines(), 1):
                        if pattern.search(line):
                            dynamic_hazards.append({"file": rel, "line": line_no, "hazard": hazard_id})
                for rule_id, pattern in SECRET_RULES:
                    for line_no, line in enumerate(text.splitlines(), 1):
                        if pattern.search(line):
                            secret_hits.append({"file": rel, "line": line_no, "rule": rule_id})

            elif suffix in {".html", ".js", ".mjs", ".ts", ".svelte", ".vue", ".css"}:
                web_files.append(rel)
                try:
                    text = fpath.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                bad_hosts = _extract_external_hosts(text, allowed_hosts)
                if bad_hosts:
                    external_url_hits.append({"file": rel, "external_hosts": bad_hosts})
                if "sourcemap" in text.lower() and ("vite.config" in rel or "webpack" in rel or "tsconfig" in rel):
                    sourcemap_configs.append(rel)
                for rule_id, pattern in SECRET_RULES:
                    for line_no, line in enumerate(text.splitlines(), 1):
                        if pattern.search(line):
                            secret_hits.append({"file": rel, "line": line_no, "rule": rule_id})

            elif suffix in {".json", ".yaml", ".yml", ".env", ".pem", ".key"} or fname.startswith(".env"):
                if fname not in {"package.json", "package-lock.json", "tsconfig.json", "protection-manifest.json"}:
                    data_candidates.append(rel)
                try:
                    text = fpath.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for rule_id, pattern in SECRET_RULES:
                    for line_no, line in enumerate(text.splitlines(), 1):
                        if pattern.search(line):
                            secret_hits.append({"file": rel, "line": line_no, "rule": rule_id})

    git_status = {"is_git_repo": False, "dirty_entries": []}
    git_exe = shutil.which("git")
    if git_exe and (project_root / ".git").exists():
        proc = subprocess.run(
            [git_exe, "-C", str(project_root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
        if proc.returncode == 0:
            git_status["is_git_repo"] = True
            git_status["dirty_entries"] = [ln for ln in proc.stdout.splitlines() if ln.strip()]

    # Recommend route heuristically based on discovered structure
    core_candidates = [p for p in py_files if "core" in p.lower() or "calc" in p.lower() or "engine" in p.lower()]
    has_pyinstaller = any(p.endswith(".spec") for p in packaging_signals)
    if has_pyinstaller:
        recommended_route = "Route C (Retain PyInstaller + compile core modules to native .pyd/.so)"
    elif core_candidates and len(core_candidates) <= max(3, len(py_files) // 2):
        recommended_route = "Route A (Compile concentrated core modules via Cython or Nuitka --module)"
    else:
        recommended_route = "Route B (Whole-application / standalone compilation via Nuitka)"

    checks = [
        {
            "check": "read_only_audit_completed",
            "status": STATUS_PASS,
            "detail": f"Scanned {len(py_files)} Python files and {len(web_files)} web files without modifying project.",
        },
        {
            "check": "frontend_offline_external_urls",
            "status": STATUS_FAIL if external_url_hits else STATUS_PASS,
            "detail": f"Found {len(external_url_hits)} web files referencing non-allowlisted external hosts.",
            "findings": external_url_hits,
        },
        {
            "check": "source_tree_secret_hygiene",
            "status": STATUS_FAIL if secret_hits else STATUS_PASS,
            "detail": f"Found {len(secret_hits)} potential secret pattern hits (values redacted).",
            "findings": secret_hits,
        },
        {
            "check": "target_platform_and_airgap_environment",
            "status": STATUS_UNVERIFIED,
            "detail": (
                f"Host OS is {platform.system()} {platform.machine()} (Python {platform.python_version()}); "
                "confirm whether deployment target OS/ABI matches before final binary build."
            ),
        },
    ]

    report = {
        "mode": "audit",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "host_environment": {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
        },
        "project_root": str(project_root),
        "git_status": git_status,
        "inventory_summary": {
            "python_files": py_files,
            "core_module_candidates": core_candidates,
            "web_files": web_files,
            "data_and_config_candidates": sorted(set(data_candidates)),
            "packaging_signals": sorted(set(packaging_signals)),
            "sourcemap_config_files": sourcemap_configs,
            "dynamic_hazards": dynamic_hazards,
        },
        "recommended_primary_route": recommended_route,
        "runtime_vs_build_offline_note": {
            "runtime_internet": "Prohibited by default; allowed local/intranet hosts: " + ", ".join(sorted(allowed_hosts)),
            "build_environment_offline": "UNSPECIFIED - record separately whether build machine must use offline wheelhouse/compiler cache.",
        },
        "checks": checks,
        "uninspected_scopes": uninspected_scopes,
        "overall_status": summarize_overall_status(checks),
    }

    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        out_file = Path(args.output).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered + "\n")
    return 0


def _compile_with_nuitka_module(
    python_exe: str,
    staged_source: Path,
    compile_out: Path,
    offline_build: bool,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    cmd = [
        python_exe,
        "-m",
        "nuitka",
        "--module",
        str(staged_source),
        f"--output-dir={compile_out}",
        "--no-pyi-file",
        "--remove-output",
    ]
    if os.name == "nt":
        cmd.append("--mingw64")
        if not offline_build:
            cmd.append("--assume-yes-for-downloads")
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env=env,
        cwd=str(compile_out),
        timeout=300,
        check=False,
    )


def _compile_with_cython_ext(
    python_exe: str,
    module_name: str,
    staged_source: Path,
    staging_root: Path,
    compile_out: Path,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    setup_script = compile_out / "_cython_build_setup.py"
    setup_code = (
        "from setuptools import Extension, setup\n"
        "from Cython.Build import cythonize\n"
        f"ext = Extension({module_name!r}, [{str(staged_source)!r}])\n"
        "setup(name='protected_ext', ext_modules=cythonize([ext], compiler_directives={'language_level': '3'}))\n"
    )
    setup_script.write_text(setup_code, encoding="utf-8")
    cmd = [
        python_exe,
        str(setup_script),
        "build_ext",
        f"--build-lib={compile_out / 'lib'}",
        f"--build-temp={compile_out / 'tmp'}",
    ]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env=env,
        cwd=str(staging_root),
        timeout=300,
        check=False,
    )


def cmd_build(args: argparse.Namespace) -> int:
    project_root = Path(args.project_root).resolve()
    manifest_path = Path(args.manifest).resolve()
    output_dir = Path(args.output_dir).resolve()
    python_exe = str(Path(args.python).resolve()) if args.python else sys.executable

    if not project_root.is_dir():
        raise ToolError(f"Project root does not exist: '{project_root}'")
    if output_dir == project_root:
        raise ToolError("--output-dir must not be the same as --project-root.")
    try:
        output_dir.relative_to(project_root)
        raise ToolError("--output-dir must be outside --project-root to keep source tree clean.")
    except ValueError:
        pass
    try:
        project_root.relative_to(output_dir)
        raise ToolError("--output-dir must not be a parent directory of --project-root.")
    except ValueError:
        pass

    manifest = load_manifest(manifest_path)
    route = args.route or manifest.get("route", "nuitka-module")
    if route not in {"nuitka-module", "cython-ext"}:
        raise ToolError(f"Unsupported route '{route}'. Expected 'nuitka-module' or 'cython-ext'.")

    if args.enable_licensing and not args.pubkey_hex:
        raise ToolError("--pubkey-hex (64 hex chars / 32-byte Ed25519 public key) is required with --enable-licensing.")
    if args.pubkey_hex:
        try:
            pub_raw = bytes.fromhex(args.pubkey_hex.strip())
        except ValueError as exc:
            raise ToolError("--pubkey-hex must be valid hexadecimal.") from exc
        if len(pub_raw) != 32:
            raise ToolError("--pubkey-hex must decode to exactly 32 bytes for Ed25519.")

    staging_dir = output_dir / "staging"
    compile_work_dir = output_dir / "compile_work"
    dist_dir = output_dir / "dist"

    plan = {
        "mode": "build",
        "dry_run": bool(args.dry_run),
        "project_root": str(project_root),
        "manifest": str(manifest_path),
        "route": route,
        "offline_build": bool(args.offline_build),
        "licensing_enabled": bool(args.enable_licensing),
        "staging_dir": str(staging_dir),
        "dist_dir": str(dist_dir),
        "protected_modules": manifest["protected_modules"],
        "runtime_files": manifest.get("runtime_files", []),
    }
    if args.dry_run:
        plan["overall_status"] = STATUS_PASS
        sys.stdout.write(json.dumps(plan, indent=2, ensure_ascii=False) + "\n")
        return 0

    output_dir.mkdir(parents=True, exist_ok=True)
    for sub in (staging_dir, compile_work_dir, dist_dir):
        if sub.exists():
            safe_rmtree(sub, output_dir, dry_run=False)
        sub.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    if os.name == "nt":
        existing_cache = env.get("NUITKA_CACHE_DIR", "")
        if not existing_cache or len(existing_cache) > 75:
            short_cache = Path(tempfile.gettempdir()) / "nk_cache"
            short_cache.mkdir(parents=True, exist_ok=True)
            env["NUITKA_CACHE_DIR"] = str(short_cache)

    ext_suffixes = tuple(s.lower() for s in importlib.machinery.EXTENSION_SUFFIXES)
    compiled_records: list[dict[str, Any]] = []

    for mod_entry in manifest["protected_modules"]:
        mod_name = mod_entry["module"]
        rel_src = mod_entry["source"]
        pkg_rel = mod_entry.get("package_dir", "")
        src_file = ensure_within_scope(project_root / rel_src, project_root, label="protected module source")
        if not src_file.is_file():
            safe_rmtree(dist_dir, output_dir, dry_run=False)
            raise ToolError(f"FAIL_CLOSED: Protected source file missing: '{src_file}'")

        staged_src = ensure_within_scope(staging_dir / rel_src, staging_dir, label="staged source")
        staged_src.parent.mkdir(parents=True, exist_ok=True)
        src_text = src_file.read_text(encoding="utf-8")

        if args.enable_licensing:
            src_text = re.sub(
                r"(?m)^REQUIRE_LICENSE_DEFAULT\s*=\s*False\s*$",
                "REQUIRE_LICENSE_DEFAULT = True",
                src_text,
            )
            src_text = re.sub(
                r'(?m)^EMBEDDED_LICENSE_PUBKEY_HEX\s*=\s*""\s*$',
                f'EMBEDDED_LICENSE_PUBKEY_HEX = "{args.pubkey_hex.strip().lower()}"',
                src_text,
            )
        staged_src.write_text(src_text, encoding="utf-8")

        mod_compile_dir = compile_work_dir / mod_name.replace(".", "_")
        mod_compile_dir.mkdir(parents=True, exist_ok=True)

        if route == "nuitka-module":
            proc = _compile_with_nuitka_module(
                python_exe=python_exe,
                staged_source=staged_src,
                compile_out=mod_compile_dir,
                offline_build=bool(args.offline_build),
                env=env,
            )
            search_root = mod_compile_dir
        else:
            proc = _compile_with_cython_ext(
                python_exe=python_exe,
                module_name=mod_name,
                staged_source=staged_src,
                staging_root=staging_dir,
                compile_out=mod_compile_dir,
                env=env,
            )
            search_root = mod_compile_dir / "lib"

        mod_leaf = mod_name.rsplit(".", 1)[-1]
        produced_binaries = []
        if search_root.is_dir():
            for cand in search_root.rglob(f"{mod_leaf}*"):
                if cand.is_file() and cand.name.lower().endswith(ext_suffixes):
                    produced_binaries.append(cand)

        if proc.returncode != 0 or len(produced_binaries) != 1:
            safe_rmtree(dist_dir, output_dir, dry_run=False)
            failure_report = {
                "mode": "build",
                "overall_status": STATUS_FAIL,
                "fail_closed": True,
                "failed_module": mod_name,
                "route": route,
                "compiler_returncode": proc.returncode,
                "produced_binaries": [str(p) for p in produced_binaries],
                "stderr_tail": redact_text((proc.stderr or "")[-2000:]),
                "stdout_tail": redact_text((proc.stdout or "")[-2000:]),
                "message": (
                    f"Compilation of protected module '{mod_name}' failed; refused fallback to .py/.pyc "
                    "and purged incomplete dist output."
                ),
            }
            sys.stdout.write(json.dumps(failure_report, indent=2, ensure_ascii=False) + "\n")
            return 2

        binary_file = produced_binaries[0]
        target_pkg_dir = ensure_within_scope(dist_dir / pkg_rel, dist_dir, label="dist package dir") if pkg_rel else dist_dir
        target_pkg_dir.mkdir(parents=True, exist_ok=True)
        dest_binary = target_pkg_dir / binary_file.name
        shutil.copy2(binary_file, dest_binary)
        compiled_records.append(
            {
                "module": mod_name,
                "artifact_relpath": dest_binary.relative_to(dist_dir).as_posix(),
                "size_bytes": dest_binary.stat().st_size,
                "sha256": sha256_file(dest_binary),
            }
        )

    protected_sources = {Path(m["source"]).as_posix() for m in manifest["protected_modules"]}
    for rel_runtime in manifest.get("runtime_files", []):
        norm_rel = Path(rel_runtime).as_posix()
        if norm_rel in protected_sources:
            safe_rmtree(dist_dir, output_dir, dry_run=False)
            raise ToolError(f"FAIL_CLOSED: Manifest lists protected source '{norm_rel}' inside runtime_files!")
        src_item = ensure_within_scope(project_root / norm_rel, project_root, label="runtime file")
        if not src_item.is_file():
            safe_rmtree(dist_dir, output_dir, dry_run=False)
            raise ToolError(f"Missing declared runtime file: '{src_item}'")
        dst_item = ensure_within_scope(dist_dir / norm_rel, dist_dir, label="dist runtime file")
        dst_item.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_item, dst_item)

    # Clean intermediate staging & compile_work directories so C/source intermediates do not linger
    safe_rmtree(staging_dir, output_dir, dry_run=False)
    safe_rmtree(compile_work_dir, output_dir, dry_run=False)

    dist_manifest_entries = []
    total_bytes = 0
    for fpath in sorted(dist_dir.rglob("*")):
        if fpath.is_file():
            size = fpath.stat().st_size
            total_bytes += size
            dist_manifest_entries.append(
                {
                    "path": fpath.relative_to(dist_dir).as_posix(),
                    "size_bytes": size,
                    "sha256": sha256_file(fpath),
                }
            )

    receipt = {
        "mode": "build",
        "overall_status": STATUS_PASS,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "route": route,
        "offline_build": bool(args.offline_build),
        "licensing_enabled": bool(args.enable_licensing),
        "reproducibility_note": "Repeatable build procedure recorded; byte-for-byte reproducibility is UNVERIFIED unless multi-build digest comparison is run.",
        "toolchain": {
            "python_executable": python_exe,
            "python_version": platform.python_version(),
            "platform": f"{platform.system()}-{platform.release()}-{platform.machine()}",
        },
        "dist_dir": str(dist_dir),
        "total_dist_bytes": total_bytes,
        "compiled_modules": compiled_records,
        "artifact_files": dist_manifest_entries,
    }
    receipt_path = output_dir / "build-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8")
    sys.stdout.write(json.dumps(receipt, indent=2, ensure_ascii=False) + "\n")
    return 0


def _iter_artifact_entries(artifact_path: Path, uninspected_scopes: list[str]) -> list[tuple[str, bytes | None]]:
    """Yield (logical_path, raw_bytes_or_None_for_binary_skip) across directories and nested archives."""
    entries: list[tuple[str, bytes | None]] = []

    def _scan_bytes_archive(logical_prefix: str, filename: str, raw: bytes, depth: int) -> None:
        if depth > 3:
            uninspected_scopes.append(f"{logical_prefix} (archive nesting depth > 3)")
            return
        lower = filename.lower()
        if lower.endswith((".zip", ".whl")):
            import io

            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        inner_name = f"{logical_prefix}!/{info.filename}"
                        if info.flag_bits & 0x1:
                            uninspected_scopes.append(f"{inner_name} (encrypted zip entry)")
                            continue
                        data = zf.read(info.filename)
                        entries.append((inner_name, data))
                        if info.filename.lower().endswith(NESTED_ARCHIVE_EXTS):
                            _scan_bytes_archive(inner_name, info.filename, data, depth + 1)
            except zipfile.BadZipFile:
                uninspected_scopes.append(f"{logical_prefix} (corrupt or unsupported zip container)")
        elif lower.endswith((".tar.gz", ".tgz", ".tar")):
            import io

            try:
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tf:
                    for member in tf.getmembers():
                        if not member.isfile():
                            continue
                        inner_name = f"{logical_prefix}!/{member.name}"
                        extracted = tf.extractfile(member)
                        if extracted is None:
                            uninspected_scopes.append(f"{inner_name} (unreadable tar member)")
                            continue
                        data = extracted.read()
                        entries.append((inner_name, data))
                        if member.name.lower().endswith(NESTED_ARCHIVE_EXTS):
                            _scan_bytes_archive(inner_name, member.name, data, depth + 1)
            except tarfile.TarError:
                uninspected_scopes.append(f"{logical_prefix} (unsupported tar container)")

    if artifact_path.is_file():
        rel_name = artifact_path.name
        raw_top = artifact_path.read_bytes()
        entries.append((rel_name, raw_top))
        if rel_name.lower().endswith(NESTED_ARCHIVE_EXTS):
            _scan_bytes_archive(rel_name, rel_name, raw_top, 1)
        elif artifact_path.suffix.lower() in OPAQUE_CONTAINER_EXTS:
            uninspected_scopes.append(f"{rel_name} (opaque binary/archive container not unpacked)")
        return entries

    for root_str, dirs, files in os.walk(artifact_path, topdown=True, followlinks=False):
        curr = Path(root_str)
        kept: list[str] = []
        for d in dirs:
            dp = curr / d
            if is_reparse_or_symlink(dp):
                uninspected_scopes.append(f"{dp.relative_to(artifact_path).as_posix()} (symlink/reparse directory)")
            else:
                kept.append(d)
        dirs[:] = kept

        for fname in sorted(files):
            fp = curr / fname
            rel = fp.relative_to(artifact_path).as_posix()
            if is_reparse_or_symlink(fp):
                uninspected_scopes.append(f"{rel} (symlink file)")
                continue
            raw = fp.read_bytes()
            entries.append((rel, raw))
            if fname.lower().endswith(NESTED_ARCHIVE_EXTS):
                _scan_bytes_archive(rel, fname, raw, 1)
            elif fp.suffix.lower() in OPAQUE_CONTAINER_EXTS:
                uninspected_scopes.append(f"{rel} (opaque binary/archive container not unpacked)")

    return entries


def cmd_inspect(args: argparse.Namespace) -> int:
    artifact_path = Path(args.artifact).resolve()
    manifest = load_manifest(Path(args.manifest).resolve())
    if not artifact_path.exists():
        raise ToolError(f"Artifact path does not exist: '{artifact_path}'")

    uninspected_scopes: list[str] = []
    entries = _iter_artifact_entries(artifact_path, uninspected_scopes)

    ext_suffixes = tuple(s.lower() for s in importlib.machinery.EXTENSION_SUFFIXES)
    protected_stems = {m["module"].rsplit(".", 1)[-1]: m["module"] for m in manifest["protected_modules"]}
    allowed_py_globs = list(manifest.get("allowed_py_globs", []))
    forbidden_assets = {Path(p).as_posix().lower() for p in manifest.get("sensitive_assets_forbidden_in_artifact", [])}
    allowed_hosts = {h.lower() for h in manifest.get("allowed_network_hosts", ["127.0.0.1", "localhost", "::1"])}

    core_leaks: list[dict[str, str]] = []
    found_native_binaries: dict[str, list[str]] = {stem: [] for stem in protected_stems}
    unallowed_py_files: list[str] = []
    sourcemap_leaks: list[dict[str, str]] = []
    external_url_leaks: list[dict[str, Any]] = []
    forbidden_asset_hits: list[str] = []
    secret_hits: list[dict[str, Any]] = []

    forbidden_core_exts = {".py", ".pyx", ".pxd", ".pyc", ".pyo", ".c", ".cpp", ".cxx", ".h", ".hpp", ".pyi"}
    raw_frontend_exts = {".ts", ".tsx", ".jsx", ".svelte", ".vue"}

    for logical_path, raw_bytes in entries:
        inner_rel = logical_path.split("!/")[-1]
        inner_norm = Path(inner_rel).as_posix()
        fname = Path(inner_norm).name
        lower_name = fname.lower()
        suffix = Path(inner_norm).suffix.lower()

        # Check native binary presence for protected stems
        for stem in protected_stems:
            if lower_name.startswith(stem.lower()) and lower_name.endswith(ext_suffixes):
                found_native_binaries[stem].append(logical_path)
            if Path(fname).stem == stem and suffix in forbidden_core_exts:
                core_leaks.append({"path": logical_path, "reason": f"Protected module '{stem}' leaked as '{suffix}'"})

        if suffix in {".c", ".cpp", ".pyx", ".pxd"} and any(s in lower_name for s in protected_stems):
            core_leaks.append({"path": logical_path, "reason": f"Generated native intermediate '{suffix}' present"})

        if suffix in {".py", ".pyc", ".pyo"}:
            if not any(fnmatch.fnmatch(inner_norm, pat) for pat in allowed_py_globs):
                unallowed_py_files.append(logical_path)

        if lower_name.endswith(".map") or suffix in raw_frontend_exts:
            sourcemap_leaks.append({"path": logical_path, "reason": f"Disallowed frontend debug/source file ({suffix})"})

        if inner_norm.lower() in forbidden_assets or lower_name.startswith(".env") or suffix in {".pem", ".key", ".pfx", ".p12"}:
            forbidden_asset_hits.append(logical_path)

        if raw_bytes is None:
            continue

        # Text-based scans for web/config/script files
        if suffix in {".html", ".js", ".mjs", ".css", ".py", ".json", ".yaml", ".yml", ".txt", ".md", ".toml", ".ini", ".cfg", ".map"} or lower_name.startswith(".env"):
            text = raw_bytes.decode("utf-8", errors="replace")
            if suffix in {".js", ".mjs", ".css"} and SOURCEMAP_DIRECTIVE_RE.search(text):
                sourcemap_leaks.append({"path": logical_path, "reason": "Inline or external sourceMappingURL directive"})
            if suffix == ".html" and HTML_SOURCE_COMMENT_RE.search(text):
                sourcemap_leaks.append({"path": logical_path, "reason": "HTML comment leaking code/debug marker"})
            if suffix in {".html", ".js", ".mjs", ".css"}:
                bad_hosts = _extract_external_hosts(text, allowed_hosts)
                if bad_hosts:
                    external_url_leaks.append({"path": logical_path, "external_hosts": bad_hosts})

            for line_no, line in enumerate(text.splitlines(), 1):
                for rule_id, pattern in SECRET_RULES:
                    if pattern.search(line):
                        secret_hits.append({"path": logical_path, "line": line_no, "rule": rule_id})

    missing_binaries = [mod for stem, mod in protected_stems.items() if not found_native_binaries[stem]]

    checks = [
        {
            "check": "protected_modules_compiled_and_source_free",
            "status": STATUS_FAIL if (core_leaks or missing_binaries) else STATUS_PASS,
            "detail": (
                f"Compiled binaries found: { {k: len(v) for k, v in found_native_binaries.items()} }; "
                f"source/C leaks: {len(core_leaks)}; missing binaries: {missing_binaries}"
            ),
            "core_leaks": core_leaks,
            "missing_binaries": missing_binaries,
        },
        {
            "check": "python_allowlist_enforcement",
            "status": STATUS_FAIL if unallowed_py_files else STATUS_PASS,
            "detail": f"Unallowlisted .py/.pyc files: {len(unallowed_py_files)}",
            "findings": unallowed_py_files,
        },
        {
            "check": "frontend_sourcemaps_and_comments",
            "status": STATUS_FAIL if sourcemap_leaks else STATUS_PASS,
            "detail": f"Frontend source map / raw source / HTML comment leaks: {len(sourcemap_leaks)}",
            "findings": sourcemap_leaks,
        },
        {
            "check": "frontend_external_network_references",
            "status": STATUS_FAIL if external_url_leaks else STATUS_PASS,
            "detail": f"External non-allowlisted URL references: {len(external_url_leaks)}",
            "findings": external_url_leaks,
        },
        {
            "check": "forbidden_sensitive_assets_and_keyfiles",
            "status": STATUS_FAIL if forbidden_asset_hits else STATUS_PASS,
            "detail": f"Forbidden standalone sensitive/key files: {len(forbidden_asset_hits)}",
            "findings": forbidden_asset_hits,
        },
        {
            "check": "redacted_secret_pattern_scan",
            "status": STATUS_FAIL if secret_hits else STATUS_PASS,
            "detail": f"Redacted secret pattern matches: {len(secret_hits)} (secret values suppressed)",
            "findings": secret_hits,
        },
        {
            "check": "nested_archive_and_container_inspection_scope",
            "status": STATUS_UNVERIFIED if uninspected_scopes else STATUS_PASS,
            "detail": (
                f"Inspected {len(entries)} entries; opaque/uninspected items: {len(uninspected_scopes)}. "
                "Note: static inspection verifies absence of raw source leaks, not impossibility of binary reverse engineering."
            ),
            "uninspected_scopes": uninspected_scopes,
        },
    ]

    overall = summarize_overall_status(checks)
    report = {
        "mode": "inspect",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "artifact": str(artifact_path),
        "inspected_entry_count": len(entries),
        "checks": checks,
        "uninspected_scopes": uninspected_scopes,
        "overall_status": overall,
    }
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered + "\n")
    return 2 if overall == STATUS_FAIL else 0


def _write_socket_guard_sitecustomize(guard_dir: Path, allowed_hosts: list[str]) -> None:
    guard_code = f"""import os
import socket

ALLOWED_HOSTS = {set(h.lower() for h in allowed_hosts)!r}
_orig_connect = socket.socket.connect
_orig_connect_ex = socket.socket.connect_ex
_orig_getaddrinfo = socket.getaddrinfo

def _is_allowed_host(host):
    if host is None:
        return True
    h = str(host).strip().lower()
    if h in ALLOWED_HOSTS or h.startswith("127.") or h == "::1":
        return True
    return False

def _guarded_connect(self, address):
    if isinstance(address, tuple) and len(address) >= 1:
        if not _is_allowed_host(address[0]):
            raise PermissionError(f"OFFLINE_SOCKET_GUARD_BLOCKED:{{address[0]}}")
    return _orig_connect(self, address)

def _guarded_connect_ex(self, address):
    if isinstance(address, tuple) and len(address) >= 1:
        if not _is_allowed_host(address[0]):
            raise PermissionError(f"OFFLINE_SOCKET_GUARD_BLOCKED:{{address[0]}}")
    return _orig_connect_ex(self, address)

def _guarded_getaddrinfo(host, port, *args, **kwargs):
    if not _is_allowed_host(host):
        raise socket.gaierror(f"OFFLINE_DNS_GUARD_BLOCKED:{{host}}")
    return _orig_getaddrinfo(host, port, *args, **kwargs)

socket.socket.connect = _guarded_connect
socket.socket.connect_ex = _guarded_connect_ex
socket.getaddrinfo = _guarded_getaddrinfo
"""
    (guard_dir / "sitecustomize.py").write_text(guard_code, encoding="utf-8")


def _set_tree_readonly(root: Path, readonly: bool) -> None:
    for p in root.rglob("*"):
        if p.is_file():
            if readonly:
                os.chmod(p, stat.S_IREAD)
            else:
                os.chmod(p, stat.S_IREAD | stat.S_IWRITE)


def _eval_generic_provenance(
    python_exe: str,
    import_root: Path,
    module_names: list[str],
    cwd_dir: Path,
    env: dict[str, str],
) -> list[dict[str, Any]]:
    probe_code = f"""
import importlib, importlib.machinery, json, pathlib
exts = tuple(s.lower() for s in importlib.machinery.EXTENSION_SUFFIXES)
records = []
for mod_name in {module_names!r}:
    mod = importlib.import_module(mod_name)
    raw_file = getattr(mod, "__file__", "") or ""
    compiled_attr = getattr(mod, "__compiled__", None)
    ext_file = getattr(compiled_attr, "extension_filename", "") if compiled_attr is not None else ""
    effective_file = str(pathlib.Path(ext_file or raw_file).resolve()) if (ext_file or raw_file) else ""
    loader_name = type(getattr(mod, "__loader__", None)).__name__
    raw_py_exists = bool(raw_file.lower().endswith(".py") and pathlib.Path(raw_file).exists())
    records.append({{
        "module": mod_name,
        "core_file": effective_file,
        "reported_dunder_file": raw_file,
        "loader": loader_name,
        "is_native_ext": bool(effective_file and pathlib.Path(effective_file).is_file() and effective_file.lower().endswith(exts) and not raw_py_exists),
    }})
print(json.dumps(records))
"""
    run_env = env.copy()
    existing_pp = run_env.get("PYTHONPATH", "")
    run_env["PYTHONPATH"] = str(import_root) + (os.pathsep + existing_pp if existing_pp else "")
    proc = subprocess.run(
        [python_exe, "-c", probe_code],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        cwd=str(cwd_dir),
        env=run_env,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        raise ToolError(f"Provenance evaluation failed (rc={proc.returncode}): {redact_text(proc.stderr)}")
    return json.loads(proc.stdout.strip())


def _eval_core_vectors(python_exe: str, import_root: Path, cwd_dir: Path, env: dict[str, str]) -> dict[str, Any]:
    probe_code = """
import importlib.machinery, json, math, os, pathlib, sys
from core import spectrum_core
from core.spectrum_core import SpectrumInputError

samples_norm = [math.sin(2.0 * math.pi * i / 8.0) + 0.1 * math.sin(4.0 * math.pi * i / 8.0) for i in range(16)]
normal = spectrum_core.analyze_harmonics(samples_norm, 1600.0, "standard")
boundary = spectrum_core.analyze_harmonics([0.0, 0.0, 0.0, 0.0], 100.0, "precision")

errors = {}
for label, args in [
    ("too_short", ([1.0, 2.0], 100.0, "standard")),
    ("neg_rate", ([1.0, 0.0, -1.0, 0.0], -10.0, "standard")),
    ("nan_val", ([1.0, float("nan"), -1.0, 0.0], 100.0, "standard")),
    ("bad_mode", ([1.0, 0.0, -1.0, 0.0], 100.0, "bogus")),
]:
    try:
        spectrum_core.analyze_harmonics(*args)
        errors[label] = "DID_NOT_RAISE"
    except SpectrumInputError as exc:
        errors[label] = f"SpectrumInputError:{exc}"

raw_file = getattr(spectrum_core, "__file__", "") or ""
compiled_attr = getattr(spectrum_core, "__compiled__", None)
ext_file = getattr(compiled_attr, "extension_filename", "") if compiled_attr is not None else ""
effective_file = str(pathlib.Path(ext_file or raw_file).resolve()) if (ext_file or raw_file) else ""
loader_name = type(getattr(spectrum_core, "__loader__", None)).__name__
exts = tuple(s.lower() for s in importlib.machinery.EXTENSION_SUFFIXES)
raw_py_exists = bool(raw_file.lower().endswith(".py") and pathlib.Path(raw_file).exists())
print(json.dumps({
    "core_file": effective_file,
    "reported_dunder_file": raw_file,
    "loader": loader_name,
    "is_native_ext": bool(effective_file and pathlib.Path(effective_file).is_file() and effective_file.lower().endswith(exts) and not raw_py_exists),
    "licensing_enabled": spectrum_core.is_licensing_enabled(),
    "normal": normal,
    "boundary": boundary,
    "errors": errors,
}))
"""
    run_env = env.copy()
    existing_pp = run_env.get("PYTHONPATH", "")
    run_env["PYTHONPATH"] = str(import_root) + (os.pathsep + existing_pp if existing_pp else "")
    proc = subprocess.run(
        [python_exe, "-c", probe_code],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        cwd=str(cwd_dir),
        env=run_env,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        raise ToolError(f"Core vector evaluation failed (rc={proc.returncode}): {redact_text(proc.stderr)}")
    return json.loads(proc.stdout.strip())


def _compare_numeric_dicts(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    abs_tol: float,
    rel_tol: float,
) -> list[str]:
    diffs: list[str] = []
    if set(baseline.keys()) != set(candidate.keys()):
        diffs.append(f"Key mismatch: {set(baseline.keys())} vs {set(candidate.keys())}")
        return diffs
    for k, bval in baseline.items():
        cval = candidate[k]
        if isinstance(bval, (int, float)) and not isinstance(bval, bool):
            if isinstance(bval, int) and isinstance(cval, int):
                if bval != cval:
                    diffs.append(f"{k}: {bval} != {cval}")
            elif not math.isclose(float(bval), float(cval), rel_tol=rel_tol, abs_tol=abs_tol):
                diffs.append(f"{k}: {bval} vs {cval} exceeds tol(abs={abs_tol}, rel={rel_tol})")
        elif bval != cval:
            diffs.append(f"{k}: {bval!r} != {cval!r}")
    return diffs


def cmd_verify_offline(args: argparse.Namespace) -> int:
    artifact_dir = Path(args.artifact).resolve()
    manifest = load_manifest(Path(args.manifest).resolve())
    python_exe = str(Path(args.python).resolve()) if args.python else sys.executable
    baseline_root = Path(args.baseline_root).resolve() if args.baseline_root else None

    if not artifact_dir.is_dir():
        raise ToolError(f"--artifact for verify-offline must be a directory: '{artifact_dir}'")

    temp_ctx = None
    if args.work_root:
        work_root = Path(args.work_root).resolve()
        work_root.mkdir(parents=True, exist_ok=True)
    else:
        temp_ctx = tempfile.TemporaryDirectory(prefix="offline_verify_")
        work_root = Path(temp_ctx.name).resolve()

    server_proc: subprocess.Popen[str] | None = None
    install_dir = work_root / "离线 验证 SpaceDir" / "app_install"
    writable_data_dir = work_root / "离线 验证 SpaceDir" / "writable_data"
    clean_cwd = work_root / "clean_cwd"
    guard_dir = work_root / "socket_guard"

    try:
        if install_dir.exists():
            _set_tree_readonly(install_dir, readonly=False)
            safe_rmtree(install_dir, work_root, dry_run=False)
        shutil.copytree(artifact_dir, install_dir)
        writable_data_dir.mkdir(parents=True, exist_ok=True)
        clean_cwd.mkdir(parents=True, exist_ok=True)
        guard_dir.mkdir(parents=True, exist_ok=True)

        allowed_hosts = list(manifest.get("allowed_network_hosts", ["127.0.0.1", "localhost", "::1"]))
        _write_socket_guard_sitecustomize(guard_dir, allowed_hosts)

        # Make install_dir files read-only to prove separation of read-only app dir vs writable APP_DATA_DIR
        _set_tree_readonly(install_dir, readonly=True)

        guarded_env = os.environ.copy()
        guarded_env["NO_PROXY"] = "*"
        guarded_env["no_proxy"] = "*"
        guarded_env["PYTHONSAFEPATH"] = "1"
        guarded_env["PYTHONDONTWRITEBYTECODE"] = "1"
        guarded_env["APP_DATA_DIR"] = str(writable_data_dir)
        guarded_env["PYTHONPATH"] = str(guard_dir)

        # 1. Verify socket guard actively blocks external internet connections
        block_probe = subprocess.run(
            [
                python_exe,
                "-c",
                "import socket\ns=socket.socket()\ntry:\n s.connect(('93.184.216.34', 80))\n print('UNBLOCKED')\nexcept PermissionError as e:\n print(str(e))",
            ],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            cwd=str(clean_cwd),
            env=guarded_env,
            timeout=15,
            check=False,
        )
        socket_guard_active = "OFFLINE_SOCKET_GUARD_BLOCKED" in (block_probe.stdout or "")

        # 2. Evaluate compiled provenance for every declared protected module from clean_cwd
        declared_mod_names = [m["module"] for m in manifest["protected_modules"]]
        prov_records = _eval_generic_provenance(python_exe, install_dir, declared_mod_names, clean_cwd, guarded_env)
        resolved_install = install_dir.resolve()
        provenance_ok = True
        for rec in prov_records:
            rec_path = Path(rec["core_file"]).resolve() if rec["core_file"] else Path()
            try:
                in_install = bool(rec["core_file"]) and rec_path.is_relative_to(resolved_install)
            except ValueError:
                in_install = False
            if not (in_install and rec["is_native_ext"] and rec["loader"] in {"ExtensionFileLoader", "nuitka_module_loader"}):
                provenance_ok = False

        # 3. Baseline parity comparison (runs built-in harmonic vectors when core.spectrum_core is present)
        tol = manifest.get("numerical_tolerance", {"abs_tol": 1e-9, "rel_tol": 1e-9})
        parity_diffs: list[str] = []
        has_fixture_core = "core.spectrum_core" in declared_mod_names
        if baseline_root and has_fixture_core:
            compiled_eval = _eval_core_vectors(python_exe, install_dir, clean_cwd, guarded_env)
            base_eval = _eval_core_vectors(python_exe, baseline_root, clean_cwd, guarded_env)
            parity_diffs.extend(
                _compare_numeric_dicts(base_eval["normal"], compiled_eval["normal"], tol["abs_tol"], tol["rel_tol"])
            )
            parity_diffs.extend(
                _compare_numeric_dicts(base_eval["boundary"], compiled_eval["boundary"], tol["abs_tol"], tol["rel_tol"])
            )
            if base_eval["errors"] != compiled_eval["errors"]:
                parity_diffs.append(f"Error semantics mismatch: {base_eval['errors']} vs {compiled_eval['errors']}")

        # 4. Launch HTTP server inside space + Chinese path with read-only install_dir
        ready_file = writable_data_dir / "server_ready.json"
        entrypoint = install_dir / manifest.get("entrypoint", "app_server.py")
        server_env = guarded_env.copy()
        server_env["PYTHONPATH"] = str(guard_dir) + os.pathsep + str(install_dir)

        t_start0 = time.perf_counter()
        server_proc = subprocess.Popen(
            [python_exe, str(entrypoint), "--host", "127.0.0.1", "--port", "0", "--ready-file", str(ready_file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            cwd=str(clean_cwd),
            env=server_env,
        )

        deadline = time.time() + 15.0
        while time.time() < deadline and not ready_file.is_file():
            if server_proc.poll() is not None:
                break
            time.sleep(0.05)
        startup_ms = round((time.perf_counter() - t_start0) * 1000.0, 2)

        if not ready_file.is_file():
            stderr_out = server_proc.stderr.read() if server_proc.stderr else ""
            raise ToolError(f"Offline HTTP server failed to start: {redact_text(stderr_out)}")

        ready_info = json.loads(ready_file.read_text(encoding="utf-8"))
        base_url = f"http://{ready_info['host']}:{ready_info['port']}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        external_web_refs: list[dict[str, Any]] = []
        allowed_set = {h.lower() for h in allowed_hosts}
        for route_path in ("/", "/static/app.js", "/static/styles.css"):
            with opener.open(f"{base_url}{route_path}", timeout=5) as resp:
                body_txt = resp.read().decode("utf-8", errors="replace")
                bad_hosts = _extract_external_hosts(body_txt, allowed_set)
                if bad_hosts:
                    external_web_refs.append({"route": route_path, "external_hosts": bad_hosts})

        with opener.open(f"{base_url}/api/health", timeout=5) as resp:
            health_json = json.loads(resp.read().decode("utf-8"))

        t_req0 = time.perf_counter()
        calc_req = urllib.request.Request(
            f"{base_url}/api/analyze",
            data=json.dumps({"samples": [0.0, 1.0, 0.0, -1.0, 0.0, 1.0, 0.0, -1.0], "sample_rate_hz": 800.0}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(calc_req, timeout=5) as resp:
            calc_json = json.loads(resp.read().decode("utf-8"))
        analyze_ms = round((time.perf_counter() - t_req0) * 1000.0, 2)

        export_req = urllib.request.Request(
            f"{base_url}/api/jobs/import-export",
            data=json.dumps(
                {
                    "job_name": "离线导出验证",
                    "records": [{"label": "ch_a", "samples": [0.0, 1.0, 0.0, -1.0], "sample_rate_hz": 400.0}],
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(export_req, timeout=5) as resp:
            export_json = json.loads(resp.read().decode("utf-8"))
        exported_file = writable_data_dir / "exports" / export_json["export_file"]

        # Verify invalid payload returns structured 400
        invalid_req = urllib.request.Request(
            f"{base_url}/api/analyze",
            data=json.dumps({"samples": [1.0], "sample_rate_hz": 800.0}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        invalid_status = 0
        try:
            opener.open(invalid_req, timeout=5)
        except urllib.error.HTTPError as http_err:
            invalid_status = http_err.code
            http_err.close()

        # 5. Port-conflict graceful exit check (without killing unrelated processes)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
            blocker.bind(("127.0.0.1", 0))
            blocker.listen(1)
            occupied_port = blocker.getsockname()[1]
            conflict_proc = subprocess.run(
                [python_exe, str(entrypoint), "--host", "127.0.0.1", "--port", str(occupied_port)],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                cwd=str(clean_cwd),
                env=server_env,
                timeout=10,
                check=False,
            )
            port_conflict_clean = conflict_proc.returncode != 0 and "BIND_ERROR" in (conflict_proc.stderr or "")

        checks = [
            {
                "check": "compiled_runtime_provenance",
                "status": STATUS_PASS if (provenance_ok and health_json.get("is_compiled_binary", True)) else STATUS_FAIL,
                "detail": f"provenance_records={prov_records}, http_is_compiled={health_json.get('is_compiled_binary')}",
            },
            {
                "check": "baseline_behavioral_and_numerical_parity",
                "status": (STATUS_PASS if not parity_diffs else STATUS_FAIL) if (baseline_root and has_fixture_core) else STATUS_UNVERIFIED,
                "detail": "100% parity on normal, boundary, and error vectors." if (baseline_root and has_fixture_core and not parity_diffs) else (
                    f"Diffs: {parity_diffs}" if parity_diffs else "Project-specific parity requires running project test vectors."
                ),
            },
            {
                "check": "scoped_offline_runtime_and_web_assets",
                "status": STATUS_PASS if (socket_guard_active and not external_web_refs and calc_json.get("ok")) else STATUS_FAIL,
                "detail": (
                    f"Outbound socket guard active={socket_guard_active}; external web refs={len(external_web_refs)}; "
                    f"HTTP analyze ok={calc_json.get('ok')}"
                ),
                "external_web_refs": external_web_refs,
            },
            {
                "check": "unicode_space_path_and_readonly_install_separation",
                "status": STATUS_PASS if exported_file.is_file() else STATUS_FAIL,
                "detail": f"Ran from '{install_dir}' (read-only files) and exported '{exported_file.name}' to writable APP_DATA_DIR.",
            },
            {
                "check": "error_handling_and_port_conflict_safety",
                "status": STATUS_PASS if (invalid_status == 400 and port_conflict_clean) else STATUS_FAIL,
                "detail": f"Invalid input HTTP status={invalid_status}; port conflict graceful exit={port_conflict_clean}.",
            },
            {
                "check": "physical_airgap_and_clean_target_machine",
                "status": STATUS_PASS if args.confirm_physical_airgap else STATUS_UNVERIFIED,
                "detail": (
                    "Verified via process-scoped outbound socket/DNS block and proxy-free loopback HTTP; "
                    "physical network disconnection and clean target OS machine without dev tools remain UNVERIFIED."
                    if not args.confirm_physical_airgap
                    else "Caller explicitly attested physical airgap clean-machine execution."
                ),
            },
        ]

        total_artifact_bytes = sum(p.stat().st_size for p in artifact_dir.rglob("*") if p.is_file())
        report = {
            "mode": "verify-offline",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "artifact": str(artifact_dir),
            "isolated_install_dir": str(install_dir),
            "writable_data_dir": str(writable_data_dir),
            "metrics": {
                "startup_ms": startup_ms,
                "analyze_request_ms": analyze_ms,
                "artifact_total_bytes": total_artifact_bytes,
                "budget_note": "No pre-existing SLA threshold configured; reporting measured latencies and byte size factually.",
            },
            "checks": checks,
            "overall_status": summarize_overall_status(checks),
        }
        rendered = json.dumps(report, indent=2, ensure_ascii=False)
        if args.output:
            out_path = Path(args.output).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")
        sys.stdout.write(rendered + "\n")
        return 2 if report["overall_status"] == STATUS_FAIL else 0

    finally:
        if server_proc is not None:
            if server_proc.poll() is None:
                server_proc.terminate()
                try:
                    server_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server_proc.kill()
                    server_proc.wait(timeout=3)
            for pipe in (server_proc.stdout, server_proc.stderr):
                if pipe is not None:
                    pipe.close()
        if install_dir.exists():
            _set_tree_readonly(install_dir, readonly=False)
        if temp_ctx is not None:
            for _ in range(15):
                try:
                    temp_ctx.cleanup()
                    break
                except PermissionError:
                    _set_tree_readonly(Path(temp_ctx.name), readonly=False)
                    time.sleep(0.1)


def cmd_clean(args: argparse.Namespace) -> int:
    build_root = Path(args.build_root).resolve()
    scope_parent = build_root.parent
    if not build_root.exists():
        sys.stdout.write(json.dumps({"mode": "clean", "dry_run": bool(args.dry_run), "removed_count": 0, "overall_status": STATUS_PASS}) + "\n")
        return 0
    if args.project_root:
        proj = Path(args.project_root).resolve()
        if build_root == proj:
            raise ToolError("Refusing to clean --project-root itself.")
        try:
            proj.relative_to(build_root)
            raise ToolError("Refusing to clean a parent directory of --project-root.")
        except ValueError:
            pass
    removed = safe_rmtree(build_root, scope_parent, dry_run=bool(args.dry_run))
    out = {
        "mode": "clean",
        "dry_run": bool(args.dry_run),
        "target": str(build_root),
        "removed_count": len(removed),
        "sample_paths": removed[:15],
        "overall_status": STATUS_PASS,
    }
    sys.stdout.write(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    return 0


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _sign_test_license(priv_key: Any, payload: dict[str, Any]) -> dict[str, str]:
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = priv_key.sign(canonical_bytes)
    return {
        "payload_b64": _b64url_encode(canonical_bytes),
        "signature_b64": _b64url_encode(sig),
    }


def cmd_license_selftest(args: argparse.Namespace) -> int:
    """Validate default-OFF licensing plus ephemeral Ed25519 core-entrypoint enforcement."""
    fixture_root = Path(args.fixture_root).resolve()
    manifest_path = fixture_root / "protection-manifest.json"
    python_exe = str(Path(args.python).resolve()) if args.python else sys.executable

    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        report = {
            "mode": "license-selftest",
            "overall_status": STATUS_UNVERIFIED,
            "detail": "PyCA cryptography is not installed in this Python interpreter.",
        }
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
        return 0

    with tempfile.TemporaryDirectory(prefix="lic_selftest_") as tmp_str:
        tmp = Path(tmp_str).resolve()
        # 1. Verify default fixture source has licensing OFF
        default_probe = subprocess.run(
            [
                python_exe,
                "-c",
                "from core import spectrum_core; assert not spectrum_core.is_licensing_enabled(); "
                "r = spectrum_core.analyze_harmonics([0.0, 1.0, 0.0, -1.0], 400.0); print(r['sample_count'])",
            ],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            cwd=str(fixture_root),
            timeout=15,
            check=False,
        )
        default_off_ok = default_probe.returncode == 0 and default_probe.stdout.strip() == "4"

        # 2. Generate ephemeral test Ed25519 keypair in temp memory/dir only
        issuer_priv = ed25519.Ed25519PrivateKey.generate()
        wrong_priv = ed25519.Ed25519PrivateKey.generate()
        pubkey_hex = issuer_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

        build_out = tmp / "licensed_build"
        build_ns = argparse.Namespace(
            project_root=str(fixture_root),
            manifest=str(manifest_path),
            output_dir=str(build_out),
            python=python_exe,
            route=args.route,
            offline_build=bool(args.offline_build),
            enable_licensing=True,
            pubkey_hex=pubkey_hex,
            dry_run=False,
        )
        rc = cmd_build(build_ns)
        if rc != 0:
            return rc

        dist_dir = build_out / "dist"
        user_data_dir = tmp / "user_data"
        user_data_dir.mkdir(parents=True, exist_ok=True)
        sentinel_file = user_data_dir / "existing_customer_project.json"
        sentinel_bytes = b'{"customer_notes": "must_never_be_deleted_or_corrupted_on_license_error"}'
        sentinel_file.write_bytes(sentinel_bytes)

        base_now = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)
        valid_payload = {
            "schema_version": 1,
            "license_id": "TEST-EPHEMERAL-001",
            "product": "mini-calc-webapp",
            "subject": "Synthetic-Test-Lab",
            "issued_at": "2026-11-01T00:00:00Z",
            "not_before": "2026-11-01T00:00:00Z",
            "expires_at": "2026-12-01T00:00:00Z",
            "features": ["core-calc"],
        }
        valid_env = _sign_test_license(issuer_priv, valid_payload)
        wrong_sig_env = _sign_test_license(wrong_priv, valid_payload)

        tampered_payload = dict(valid_payload, expires_at="2099-12-31T00:00:00Z")
        tampered_env = {
            "payload_b64": _b64url_encode(json.dumps(tampered_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")),
            "signature_b64": valid_env["signature_b64"],
        }
        wrong_scope_env = _sign_test_license(issuer_priv, dict(valid_payload, features=["viewer-only"]))
        bool_ver_env = _sign_test_license(issuer_priv, dict(valid_payload, schema_version=True))

        cases_json = json.dumps(
            {
                "valid": valid_env,
                "wrong_sig": wrong_sig_env,
                "tampered": tampered_env,
                "wrong_scope": wrong_scope_env,
                "bool_ver": bool_ver_env,
                "now_valid": base_now.isoformat(),
                "now_expired": (base_now + timedelta(days=45)).isoformat(),
            }
        )

        # 3. Direct compiled-core bypass & edge-case matrix from outside source tree
        direct_test_code = f"""
import importlib.machinery, json, os, pathlib
from datetime import datetime
from core import spectrum_core
from core.spectrum_core import LicenseVerificationError

cases = json.loads({cases_json!r})
now_valid = datetime.fromisoformat(cases["now_valid"])
now_expired = datetime.fromisoformat(cases["now_expired"])

compiled_attr = getattr(spectrum_core, "__compiled__", None)
ext_path = getattr(compiled_attr, "extension_filename", "") if compiled_attr is not None else ""
eff_path = str(pathlib.Path(ext_path or spectrum_core.__file__).resolve())

results = {{
    "is_compiled_ext": eff_path.lower().endswith(tuple(s.lower() for s in importlib.machinery.EXTENSION_SUFFIXES)) and pathlib.Path(eff_path).is_file(),
    "licensing_enabled": spectrum_core.is_licensing_enabled(),
}}

# Valid call
res_ok = spectrum_core.analyze_harmonics([0.0, 1.0, 0.0, -1.0], 400.0, license_envelope=cases["valid"], now_utc=now_valid)
results["valid_call"] = res_ok["sample_count"] == 4

for name, env_val, ts in [
    ("direct_bypass_missing_license", None, now_valid),
    ("wrong_signature", cases["wrong_sig"], now_valid),
    ("tampered_payload", cases["tampered"], now_valid),
    ("malformed_json", "{{not-json", now_valid),
    ("boolean_schema_version", cases["bool_ver"], now_valid),
    ("wrong_feature_scope", cases["wrong_scope"], now_valid),
    ("expired_injected_clock", cases["valid"], now_expired),
]:
    try:
        spectrum_core.analyze_harmonics([0.0, 1.0, 0.0, -1.0], 400.0, license_envelope=env_val, now_utc=ts)
        results[name] = False
    except LicenseVerificationError:
        results[name] = True

print(json.dumps(results))
"""
        run_env = os.environ.copy()
        run_env["PYTHONPATH"] = str(dist_dir)
        run_env["PYTHONSAFEPATH"] = "1"
        run_env["APP_DATA_DIR"] = str(user_data_dir)
        run_env.pop("MINI_CALC_LICENSE_FILE", None)

        direct_proc = subprocess.run(
            [python_exe, "-c", direct_test_code],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            cwd=str(tmp),
            env=run_env,
            timeout=30,
            check=False,
        )
        if direct_proc.returncode != 0:
            raise ToolError(f"Direct core license matrix failed: {redact_text(direct_proc.stderr)}")

        matrix = json.loads(direct_proc.stdout.splitlines()[-1])
        user_data_intact = sentinel_file.is_file() and sentinel_file.read_bytes() == sentinel_bytes

        checks = [
            {
                "check": "default_licensing_disabled",
                "status": STATUS_PASS if default_off_ok else STATUS_FAIL,
                "detail": f"Unlicensed default mode unrestricted={default_off_ok}.",
            },
            {
                "check": "compiled_core_ed25519_matrix_and_direct_bypass_block",
                "status": STATUS_PASS if all(matrix.values()) else STATUS_FAIL,
                "detail": "Tested valid, direct Python core bypass without UI, bad signature, tampered payload, malformed JSON, bool version, wrong scope, and injected-clock expiry.",
                "matrix": matrix,
            },
            {
                "check": "non_destructive_user_data_preservation",
                "status": STATUS_PASS if user_data_intact else STATUS_FAIL,
                "detail": f"Pre-existing customer data file preserved byte-for-byte={user_data_intact}.",
            },
        ]
        summary = {
            "mode": "license-selftest",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "checks": checks,
            "overall_status": summarize_overall_status(checks),
        }
        if args.output:
            out_path = Path(args.output).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        sys.stdout.write(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
        return 2 if summary["overall_status"] == STATUS_FAIL else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="offline_protect_tool.py",
        description="Audit, build, inspect, and offline-verify Python + JS web app deliveries.",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_audit = sub.add_parser("audit", help="Read-only project reconnaissance and hazard/leak surface scan.")
    p_audit.add_argument("--project-root", required=True, help="Path to target project root (read-only).")
    p_audit.add_argument("--allow-host", action="append", help="Allowed runtime host (repeatable; defaults to localhost).")
    p_audit.add_argument("--output", help="Optional JSON report path (must be outside --project-root).")
    p_audit.set_defaults(func=cmd_audit)

    p_build = sub.add_parser("build", help="Compile protected core modules fail-closed into an isolated dist folder.")
    p_build.add_argument("--project-root", required=True, help="Source project root (kept unmodified).")
    p_build.add_argument("--manifest", required=True, help="Path to protection-manifest.json.")
    p_build.add_argument("--output-dir", required=True, help="Dedicated build output directory outside --project-root.")
    p_build.add_argument("--python", help="Python interpreter with Nuitka/Cython installed.")
    p_build.add_argument("--route", choices=["nuitka-module", "cython-ext"], help="Override manifest compilation route.")
    p_build.add_argument("--offline-build", action="store_true", help="Forbid compiler toolchain auto-downloads during build.")
    p_build.add_argument("--enable-licensing", action="store_true", help="Opt-in: compile embedded Ed25519 verifier into core.")
    p_build.add_argument("--pubkey-hex", default="", help="32-byte hex Ed25519 public key when --enable-licensing is set.")
    p_build.add_argument("--dry-run", action="store_true", help="Preview build & staging plan without writing or deleting files.")
    p_build.set_defaults(func=cmd_build)

    p_inspect = sub.add_parser("inspect", help="Inspect delivery folder and nested archives for source, map, or secret leaks.")
    p_inspect.add_argument("--artifact", required=True, help="Delivery directory or archive to inspect.")
    p_inspect.add_argument("--manifest", required=True, help="Path to protection-manifest.json.")
    p_inspect.add_argument("--output", help="Optional JSON report output path.")
    p_inspect.set_defaults(func=cmd_inspect)

    p_verify = sub.add_parser("verify-offline", help="Run isolated provenance, parity, Unicode/space path, and socket-guarded offline checks.")
    p_verify.add_argument("--artifact", required=True, help="Staged delivery directory to verify.")
    p_verify.add_argument("--manifest", required=True, help="Path to protection-manifest.json.")
    p_verify.add_argument("--baseline-root", help="Optional source root for numerical/error parity comparison.")
    p_verify.add_argument("--python", help="Python interpreter to execute tests.")
    p_verify.add_argument("--work-root", help="Optional isolated working directory for runtime verification.")
    p_verify.add_argument("--confirm-physical-airgap", action="store_true", help="Set only when actually executing on a physically disconnected target machine.")
    p_verify.add_argument("--output", help="Optional JSON report output path.")
    p_verify.set_defaults(func=cmd_verify_offline)

    p_clean = sub.add_parser("clean", help="Safely remove a dedicated build directory without following symlinks.")
    p_clean.add_argument("--build-root", required=True, help="Build output directory to remove.")
    p_clean.add_argument("--project-root", help="Optional project root guard to prevent accidental source deletion.")
    p_clean.add_argument("--dry-run", action="store_true", help="List files/directories that would be removed without deleting.")
    p_clean.set_defaults(func=cmd_clean)

    p_lic = sub.add_parser("license-selftest", help="Run opt-in ephemeral Ed25519 core licensing & bypass verification on fixture.")
    p_lic.add_argument("--fixture-root", required=True, help="Path to mini_calc_webapp fixture directory.")
    p_lic.add_argument("--python", help="Python interpreter with Nuitka/Cython + cryptography installed.")
    p_lic.add_argument("--route", choices=["nuitka-module", "cython-ext"], default="nuitka-module")
    p_lic.add_argument("--offline-build", action="store_true")
    p_lic.add_argument("--output", help="Optional JSON report output path.")
    p_lic.set_defaults(func=cmd_license_selftest)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ToolError as exc:
        err_payload = {
            "overall_status": STATUS_FAIL,
            "error": redact_text(str(exc)),
        }
        sys.stderr.write(json.dumps(err_payload, ensure_ascii=False) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
