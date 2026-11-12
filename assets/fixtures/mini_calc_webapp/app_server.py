"""Local HTTP backend for the synthetic offline Python + JS web application fixture."""

from __future__ import annotations

import argparse
import importlib.machinery
import json
import os
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from core import spectrum_core
from core.spectrum_core import LicenseVerificationError, SpectrumInputError
from vendor_runtime.unit_labels import format_unit


def resolve_static_dir() -> Path:
    override = os.environ.get("APP_STATIC_DIR", "").strip()
    if override:
        return Path(override).resolve()
    return (Path(__file__).resolve().parent / "web").resolve()


def resolve_data_dir() -> Path:
    override = os.environ.get("APP_DATA_DIR", "").strip()
    if override:
        return Path(override).resolve()
    return (Path(__file__).resolve().parent / "runtime_data").resolve()


def get_core_provenance() -> dict[str, Any]:
    raw_file = getattr(spectrum_core, "__file__", "") or ""
    loader_obj = getattr(spectrum_core, "__loader__", None)
    loader_name = type(loader_obj).__name__ if loader_obj is not None else "None"
    compiled_attr = getattr(spectrum_core, "__compiled__", None)
    ext_filename = getattr(compiled_attr, "extension_filename", "") if compiled_attr is not None else ""

    effective_path_str = ext_filename or raw_file
    resolved_binary = str(Path(effective_path_str).resolve()) if effective_path_str else ""
    ext_suffixes = tuple(s.lower() for s in importlib.machinery.EXTENSION_SUFFIXES)
    is_native_ext = bool(
        resolved_binary
        and Path(resolved_binary).is_file()
        and resolved_binary.lower().endswith(ext_suffixes)
    )
    raw_py_absent = not (raw_file.lower().endswith(".py") and Path(raw_file).exists())
    is_compiled_loader = loader_name in {"ExtensionFileLoader", "nuitka_module_loader"} or (
        "nuitka" in loader_name.lower()
    )
    return {
        "module": spectrum_core.__name__,
        "core_file": resolved_binary,
        "reported_dunder_file": raw_file,
        "core_loader": loader_name,
        "is_compiled_binary": bool(is_native_ext and is_compiled_loader and raw_py_absent),
        "licensing_enabled": spectrum_core.is_licensing_enabled(),
    }


class MiniCalcHandler(BaseHTTPRequestHandler):
    server_version = "MiniCalcOffline/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        if os.environ.get("MINI_CALC_QUIET", "1") == "1":
            return
        super().log_message(fmt, *args)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _send_static(self, rel_path: str, content_type: str) -> None:
        static_root = resolve_static_dir()
        candidate = (static_root / rel_path).resolve()
        try:
            candidate.relative_to(static_root)
        except ValueError:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "Forbidden path."})
            return
        if not candidate.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Asset '{rel_path}' not found."})
            return
        data = candidate.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json_body(self) -> dict[str, Any]:
        length_str = self.headers.get("Content-Length", "0")
        try:
            length = int(length_str)
        except ValueError as exc:
            raise SpectrumInputError("Invalid Content-Length header.") from exc
        if length <= 0 or length > 262144:
            raise SpectrumInputError("Request body size must be between 1 and 262144 bytes.")
        raw = self.rfile.read(length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SpectrumInputError("Request body must be valid UTF-8 JSON.") from exc
        if not isinstance(parsed, dict):
            raise SpectrumInputError("Request JSON root must be an object.")
        return parsed

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in {"/", "/index.html"}:
            self._send_static("index.html", "text/html; charset=utf-8")
            return
        if path == "/static/app.js":
            self._send_static("app.js", "application/javascript; charset=utf-8")
            return
        if path == "/static/styles.css":
            self._send_static("styles.css", "text/css; charset=utf-8")
            return
        if path == "/api/health":
            data_dir = resolve_data_dir()
            provenance = get_core_provenance()
            provenance["status"] = "ok"
            provenance["units"] = {
                "frequency": format_unit("hz"),
                "amplitude": format_unit("rms"),
            }
            provenance["data_dir"] = str(data_dir)
            self._send_json(HTTPStatus.OK, provenance)
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Route not found."})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        try:
            body = self._read_json_body()
            if path == "/api/analyze":
                result = spectrum_core.analyze_harmonics(
                    samples=body.get("samples"),  # type: ignore[arg-type]
                    sample_rate_hz=body.get("sample_rate_hz"),  # type: ignore[arg-type]
                    mode=body.get("mode", "standard"),
                    license_envelope=body.get("license_envelope"),
                )
                result["units"] = {
                    "fundamental_hz": format_unit("hz"),
                    "calibrated_rms": format_unit("rms"),
                }
                self._send_json(HTTPStatus.OK, {"ok": True, "result": result})
                return

            if path == "/api/jobs/import-export":
                job_name = str(body.get("job_name", "batch_job")).strip() or "batch_job"
                safe_slug = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in job_name)[:48]
                records = body.get("records")
                if not isinstance(records, list) or not records or len(records) > 32:
                    raise SpectrumInputError("records must be a non-empty list of at most 32 items.")

                computed_rows = []
                for item in records:
                    if not isinstance(item, dict):
                        raise SpectrumInputError("Each record must be an object.")
                    res = spectrum_core.analyze_harmonics(
                        samples=item.get("samples"),  # type: ignore[arg-type]
                        sample_rate_hz=item.get("sample_rate_hz", 1000.0),
                        mode=item.get("mode", "standard"),
                        license_envelope=body.get("license_envelope"),
                    )
                    computed_rows.append({"label": str(item.get("label", "ch0")), "metrics": res})

                export_dir = resolve_data_dir() / "exports"
                export_dir.mkdir(parents=True, exist_ok=True)
                export_path = export_dir / f"{safe_slug}_report.json"
                export_doc = {
                    "job_name": job_name,
                    "record_count": len(computed_rows),
                    "results": computed_rows,
                }
                export_path.write_text(json.dumps(export_doc, indent=2, ensure_ascii=False), encoding="utf-8")
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "export_file": export_path.name,
                        "record_count": len(computed_rows),
                        "results": computed_rows,
                    },
                )
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Unknown API endpoint."})
        except LicenseVerificationError as exc:
            self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error_type": "license_error", "error": str(exc)})
        except SpectrumInputError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error_type": "validation_error", "error": str(exc)})
        except OSError as exc:
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"ok": False, "error_type": "storage_error", "error": f"Data storage error: {exc.strerror or 'I/O'}"},
            )


def create_server(host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), MiniCalcHandler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Mini Calc offline HTTP server.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=18080, help="TCP port (0 selects an ephemeral free port).")
    parser.add_argument("--ready-file", default="", help="Optional path to write bound host:port JSON on startup.")
    args = parser.parse_args(argv)

    try:
        server = create_server(args.host, args.port)
    except OSError as exc:
        sys.stderr.write(f"BIND_ERROR: Could not bind {args.host}:{args.port} ({exc})\n")
        return 2

    bound_host, bound_port = server.server_address[:2]
    if args.ready_file:
        ready_path = Path(args.ready_file)
        ready_path.parent.mkdir(parents=True, exist_ok=True)
        ready_path.write_text(
            json.dumps({"host": bound_host, "port": bound_port, "pid": os.getpid()}),
            encoding="utf-8",
        )

    sys.stdout.write(f"READY http://{bound_host}:{bound_port}\n")
    sys.stdout.flush()
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
