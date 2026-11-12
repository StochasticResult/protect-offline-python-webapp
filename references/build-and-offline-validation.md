# Build Pipeline, Artifact Leak Inspection & Offline Validation

Read this reference during **Step 3 (Baseline)**, **Step 4 (Isolated Build)**, and **Step 6 (Artifact Inspection & Offline Acceptance)**.

## 1. Keep Runtime Offline Separate from Build Offline

Record and verify these two dimensions independently in every audit and build report:

| Dimension | Question Answered | Typical Requirements & Verification |
| :--- | :--- | :--- |
| **Runtime Network Policy** | What network endpoints may the delivered application contact while running? | **Zero public internet**. Explicitly list allowed local/intranet endpoints (e.g., `127.0.0.1:<port>`, LAN database `10.x.x.x:5432`, NAS mount, local LLM `127.0.0.1:1234`, GPIB/VISA/Modbus instrument IPs). Block or flag all external DNS/HTTP/HTTPS/WebSocket traffic (`cdn.*`, Google Fonts, Sentry/PostHog telemetry, auto-updaters, HuggingFace hub downloads). |
| **Build Environment Connectivity** | Must the build/CI machine itself run without internet access? | **Online build allowed**: Pin versions via lockfiles; compilers/wheels/npm packages may be fetched at build time (pass `--assume-yes-for-downloads` if Nuitka downloads cached toolchains on Windows). **Offline build required**: Pre-populate pip wheelhouse (`pip download` / `--no-index --find-links`), npm offline cache/tarballs, and pre-staged C/C++ compiler + `NUITKA_CACHE_DIR` before disconnecting. |

## 2. Protected Module & Asset Inventory + Tool Manifest

Before modifying any build step, document a **Protected Module & Asset Inventory** table:

| Item / Path | Asset Class | Protection Goal (`G1`–`G4`) | Current Exposure | Planned Treatment | Acceptance Check |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `core/spectrum_core.py` | Core algorithm | `G1`, `G2` | Raw `.py` in release folder | Compile to native `.pyd`/`.so`; strip `.py`/`.c`/`.pyi` | `ExtensionFileLoader` / compiled loader provenance; zero `.py`/`.c` in artifact |
| `core/calibration_rules.json` | Rule / coeff table | `G4` | Plain JSON file | Embed constants inside compiled `spectrum_core` binary | Standalone JSON absent from artifact; API parity holds |
| `web/` | Frontend UI | Offline completeness | Static HTML/JS/CSS | Bundle locally without `.map` or CDN links | Zero `.map`/`sourceMappingURL`/external URLs |

### Minimal Manifest for `scripts/offline_protect_tool.py` (`protection-manifest.json`)

Prefer the project's existing build scripts (`pyproject.toml`, `Makefile`, release scripts). When using the bundled `scripts/offline_protect_tool.py`, supply `protection-manifest.json`.

> **Important**: `protection-manifest.json` is **only** the input schema for `scripts/offline_protect_tool.py` bundled with this skill—it is **not** a native configuration file recognized directly by Nuitka, Cython, or PyInstaller.

```json
{
  "schema_version": 1,
  "project_name": "mini-calc-webapp",
  "route": "nuitka-module",
  "entrypoint": "app_server.py",
  "protected_modules": [
    {
      "module": "core.spectrum_core",
      "source": "core/spectrum_core.py",
      "package_dir": "core"
    }
  ],
  "runtime_files": [
    "app_server.py",
    "core/__init__.py",
    "web/index.html",
    "web/app.js",
    "web/styles.css",
    "THIRD_PARTY_NOTICES.txt"
  ],
  "sensitive_assets_forbidden_in_artifact": [
    "core/dev_calibration_notes.json"
  ],
  "allowed_py_globs": [
    "app_server.py",
    "core/__init__.py",
    "vendor_runtime/*.py"
  ],
  "allowed_network_hosts": [
    "127.0.0.1",
    "localhost",
    "::1"
  ],
  "numerical_tolerance": {
    "abs_tol": 1e-9,
    "rel_tol": 1e-9
  }
}
```

## 3. Baseline, Staging Isolation & Safe Cleanup

1. **Baseline First**:
   - Execute existing unit/API tests before compiling anything. Capture deterministic outputs for normal inputs, boundary values (zeros, extremes, empty collections, Unicode names), and invalid inputs (HTTP `400`/`422` error codes and exception messages), plus startup time, key endpoint latency, and artifact byte size.
2. **Staging & Path-Containment Guards**:
   - Write all intermediate `.c`, `.o`, `.build`, and staged release trees inside an explicit build workspace (e.g., `<build-root>/staging` and `<build-root>/dist`).
   - Keep Windows compiler caches (`NUITKA_CACHE_DIR`, `TEMP`) on short paths (`< 80` chars) so extracted MinGW64/Windows SDK headers do not exceed legacy 260-character `MAX_PATH` limits.
   - Before deleting any directory during build or rollback:
     - Support `--dry-run` in `offline_protect_tool.py` to list candidate removals without touching disk.
     - Resolve paths via `Path.resolve()` and verify strict containment inside the authorized build output scope.
     - Check `os.path.islink()` and Windows reparse-point attributes (`FILE_ATTRIBUTE_REPARSE_POINT = 0x400`) before recursion—never follow symlinks or NTFS junctions outside the staging tree, and never delete user data directories or uncommitted source edits.
3. **Fail-Closed Compilation Gate**:
   - Every module listed in `protected_modules` must produce a verified compiled binary matching the target Python ABI/platform, and its `.py`, `.pyx`, `.pxd`, `.pyc`, `.c`, `.cpp`, and `.pyi` (when internal signatures should not be exposed; e.g., Nuitka `--no-pyi-file`) must be absent from the final staged artifact.
   - If compilation exits non-zero or produces no native binary, abort immediately with `FAIL` and non-zero exit code. Never copy the `.py` file into `dist/` as a fallback.

## 4. Proving Runtime Provenance (Not Just File Suffixes)

Never assume an application is running compiled code merely because a `.pyd` or `.so` file exists on disk—Python's `sys.path` can silently import raw `.py` from the developer's working directory or `PYTHONPATH`.

Collect runtime provenance proof from a **separate working directory** outside the source checkout with `PYTHONSAFEPATH=1` (Python 3.11+) or sanitized `PYTHONPATH`:
1. Import each protected module inside the running artifact process and inspect tool-specific loader attributes rather than relying on `__file__` suffixes alone:
   - **Cython (`ExtensionFileLoader`)**: `type(module.__loader__).__name__ == "ExtensionFileLoader"` and `Path(module.__file__).resolve()` points to an existing `.pyd`/`.so` file inside the staged artifact directory.
   - **Nuitka (`nuitka_module_loader`, verified on Nuitka `4.3.5`)**: Nuitka rewrites `module.__file__` and `module.__spec__.origin` at runtime to a synthetic `<dir>/<mod>.py` compatibility path even when no `.py` file exists on disk. Verify `type(module.__loader__).__name__ == "nuitka_module_loader"`, inspect `Path(module.__compiled__.extension_filename).resolve()` (for `--module` builds) or `module.__compiled__.containing_dir` (for `--standalone`), confirm that native binary exists inside the staged artifact directory (resolving Windows `8.3` short paths via `Path.resolve()`), and confirm the synthetic `.py` path does **not** exist on disk.
   - Never accept `SourceFileLoader`, `SourcelessFileLoader`, or any path resolving back to the developer source checkout.

## 5. Artifact & Internal Archive Leak Checklist

Inspect both top-level directories and nested archives (`.zip`, `.whl`, `.tar`, `.tar.gz`, `.tgz`):

- **Protected core leaks (`FAIL`)**: Any protected module present as `.py`, `.pyx`, `.pxd`, `.pyc`, `.pyo`, `.c`, `.cpp`, `.h`, or `.build/` directory inside the artifact or nested archive.
- **Frontend source maps & debug leaks (`FAIL`)**:
  - Standalone `*.js.map`, `*.css.map`, `*.mjs.map` files (note: Vite `build.sourcemap: 'hidden'` suppresses comments in `.js` but **still writes `.map` files** to `dist/`!).
  - Inline or external `//# sourceMappingURL=` / `/*# sourceMappingURL=` directives (including `data:application/json;base64,...`).
  - Original `.ts`, `.tsx`, `.svelte`, `.vue`, `.jsx` sources accidentally copied into static web roots.
- **Secrets, keys & dev artifacts (`FAIL`, redacted output)**:
  - PEM/PKCS private keys (`-----BEGIN ... PRIVATE KEY-----`), `.pem`, `.key`, `.pfx`, `.p12`, `.env*`, CI tokens, hardcoded DSNs/API keys, or test credentials.
  - **Redaction Rule**: Log only `<relative-path>:<line> [<rule-id>]`—never print the matched secret value or raw environment variables.
- **Sensitive standalone assets (`FAIL`)**: Any file matching `sensitive_assets_forbidden_in_artifact` (unbundled JSON rule sets, raw prompt libraries, unencrypted calibration tables, dev SQLite DBs).
- **Allowlist & Open-Source Compliance**:
  - Allow outer Python entrypoints, `__init__.py` package markers, and third-party vendor `.py`/`.json`/metadata files explicitly covered by `allowed_py_globs`, while preserving required `LICENSE` / `THIRD_PARTY_NOTICES` files.
- **Uninspected Containers (`UNVERIFIED`)**:
  - When an artifact contains opaque executables (`.exe`, ELF onefile payloads, PyInstaller `PYZ` containers without extractor run, encrypted archives, or installer `.msi`/`.dmg` blobs not unpacked by the scanner), explicitly list each path under `UNVERIFIED` scope rather than declaring zero leaks.

## 6. Offline Runtime Acceptance Protocol

Execute and report each check explicitly without modifying host-wide firewall rules, network adapters, or OS system time:

1. **Outbound Network Guard (`Process-Scoped`)**:
   - Set `NO_PROXY=*` and disable auto-update/telemetry env vars.
   - Wrap test execution (or inject `sitecustomize.py` in an isolated test `PYTHONPATH`) with a socket guard that rejects `socket.connect` / `socket.create_connection` / `getaddrinfo` to any host outside `allowed_network_hosts` (`127.0.0.1`, `localhost`, `::1`, plus project-declared LAN IPs).
   - Scan HTML/JS/CSS and HTTP responses for external `http://`, `https://`, `wss://`, or protocol-relative `//` URLs (CDNs, Google Fonts, external analytics).
   - **Honest Scope Reporting**: Process socket guards + browser request interception prove application-level behavior for exercised code paths (`PASS` for scoped offline test), **not** whole-OS physical airgap or unexercised native C `connect()` syscalls. Mark physical airgap / clean target-OS machine testing `UNVERIFIED` unless actually run on a disconnected target machine.
2. **Filesystem & Path Resilience**:
   - Run the packaged artifact from an external directory whose path contains **spaces and non-ASCII characters** (e.g., `离线 验证 SpaceDir/`).
   - Verify separation between **read-only application install directory** and **writable user data/log/export directory** (`APP_DATA_DIR`) when applicable to the deployment model.
3. **Functional, Error & Port-Conflict Behavior**:
   - Exercise real HTTP page load, static JS/CSS asset fetch, core calculation APIs, and data import/export flows.
   - Verify invalid request payloads return expected structured errors without leaking stack traces or crashing the worker.
   - Bind a temporary ephemeral loopback socket first to simulate a **port conflict**, start a second server instance pointed at that occupied port, verify clean error exit, and ensure cleanup terminates **only** the child process spawned by the test (`proc.terminate()` / `proc.wait()`), never running broad `taskkill /IM python.exe` or `pkill python`.
4. **Numerical Parity, Performance & Reproducibility**:
   - Compare compiled vs. baseline outputs within documented tolerances (`math.isclose(..., rel_tol=..., abs_tol=...)` for floating-point math; exact match for integers, enums, and status codes).
   - Report measured startup time, request latency, and artifact size + SHA-256 checksums. Compare against existing project budgets if defined; otherwise report measurements and regressions factually without inventing user-approved SLA thresholds.
   - Record exact Python, compiler, and dependency versions. Describe the build as **repeatable** unless two independent builds have been verified to produce identical SHA-256 digests (**byte-for-byte reproducible**).
