# Threat Model, Route Selection & Capability Boundaries

Read this reference during **Step 1 (Inventory)** and **Step 2 (Route Selection)** before choosing compilation or packaging tools.

## 1. Separate the Four Protection Goals

Never collapse "protect our software" into a single vague claim. Evaluate and verify each goal independently:

| Goal ID | Security Goal | Primary Engineering Mechanism | What It Does **Not** Do |
| :--- | :--- | :--- | :--- |
| **G1** | Reduce direct access to proprietary source files | Compile core `.py` to native `.pyd`/`.so` or standalone native binary; strip `.py`/`.pyx`/`.c`/`.map` from artifacts | Does not stop binary disassembly/decompilation or dynamic observation |
| **G2** | Raise cost of understanding, modifying, or cloning core algorithms | Native C/machine compilation (Cython / Nuitka), symbol stripping, consolidating sensitive domain math/rules inside native modules | Cannot guarantee "irreversible" or "AI-unbreakable" secrecy; makes analysis slower and more specialized |
| **G3** | Restrict unauthorized execution or casual copying | Server-side isolation (when provider controls host) or opt-in signed offline licensing enforced inside compiled core entrypoints | Native `.pyd`/`.so` modules without authorization checks can still be `import`ed and called directly by local Python scripts |
| **G4** | Protect rule tables, calibration coefficients, weights, prompts, and data assets | Embed small static constants/tables into compiled native code, keep server-only assets on trusted hosts, or apply authenticated encryption where keys are provisioned per authorized environment | Any asset decrypted into process memory on a customer-administered machine can eventually be dumped by a local administrator/debugger |

## 2. Trust & Execution Environment Boundaries

1. **Browser Surface Is Public to the User**:
   - All JavaScript, CSS, WebAssembly (`.wasm`), HTML templates, fonts, and API payloads delivered to the browser are inspectable and modifiable via DevTools or local proxies.
   - Minification or JS bundling removes comments/symbols and reduces bundle size; never rely on disabling right-click, `debugger` traps, hidden DOM buttons, or frontend-only license flags as security boundaries.
   - Do **not** port existing Python algorithms into browser Wasm purely to "hide" them—shipping Wasm moves proprietary logic onto the client device where every byte is downloadable.
2. **Customer-Controlled Host vs. Provider-Controlled Offline Server**:
   - **Customer controls backend machine** (desktop local server, customer IT VM/appliance with root/Administrator access): A `127.0.0.1` or LAN Python process is **not** a trusted enclave against that customer. Protection only raises reverse-engineering and tampering cost.
   - **Provider or trusted ops controls offline server** (on-prem locked appliance or internal server where target users only have browser/HTTP access and lack OS admin rights, filesystem read access to app binaries, and debuggers): Keep sensitive algorithms, models, and rule tables strictly on the server and expose minimal API outputs. Never assume "intranet server deployment" equals trusted isolation until actual admin/file/debug access ownership is verified.
3. **Direct Module Invocation vs. Reverse Engineering**:
   - Compiling `pricing_core.py` into `pricing_core.cp312-win_amd64.pyd` hides Python source (**G1/G2**), but anyone with local file access and a matching Python ABI can still run `import pricing_core; pricing_core.compute(...)` unless execution context or authorization (**G3**) is separately controlled.
4. **Prohibited Claims**:
   - Never state or imply "impossible to decompile", "100% irreversible", "immune to AI reverse engineering", "permanent secret protection", or unverified quantitative claims (e.g., "10x harder to crack" or "takes 6 months to reverse").

## 3. Primary Compilation & Packaging Routes

Choose **one** primary route based on empirical codebase structure rather than stacking multiple obfuscators blindly:

### Route A — Concentrated Core + Native Extension Modules (`.pyd` / `.so`)
- **Best fit**: Core IP (numerical solvers, signal/RF math, scoring engines, proprietary parsers/rules) lives in a bounded set of modules with stable function/data interfaces, while outer FastAPI/Flask/Django/ASGI glue handles routing, ORM, and I/O.
- **Mechanism**: Compile declared core modules to C and native shared libraries using **Cython** (`cythonize` + C compiler) or **Nuitka module mode** (`python -m nuitka --module pkg/core.py`). Deliver outer service glue with existing packaging/venv/wheel/container/directory release.
- **Advantages**: Fast incremental builds, minimal framework compatibility risk (Pydantic/FastAPI/SQLAlchemy annotations in outer routers remain untouched), straightforward A/B behavioral verification.
- **Watchouts**:
  - Do not leave `core.py`, `core.pyx`, `core.c`, or `core.pyc` alongside `core.<abi>.pyd`/`.so` in the final package.
  - Native extensions are bound to OS, CPU architecture, and CPython minor ABI (e.g., `cp312-win_amd64` vs `cp312-manylinux_x86_64`), unless explicitly built targeting the Python Stable ABI (`abi3`) and verified.
  - On Windows, deep cache or build paths exceeding legacy 260-char `MAX_PATH` limits can break MinGW64/MSVC header resolution (`psdk_inc/intrin-impl.h`); keep compiler cache and build directories on short paths when needed.

### Route B — Dispersed Python Business Logic + Nuitka Standalone / Whole-App Compilation
- **Best fit**: Proprietary business rules are spread across many service modules, making core extraction invasive, OR the target requires a self-contained directory distribution without pre-installed Python on the target machine.
- **Mechanism**: **Nuitka** (`--standalone`, optionally `--onefile` only if explicitly required) compiles Python modules into C and links a standalone binary + embedded runtime directory (`*.dist`).
- **Advantages**: Preserves multi-module architecture with few source changes; produces self-contained directory deployments suitable for clean offline machines.
- **Watchouts**:
  - Verify via Nuitka compilation reports (`--report=compilation-report.xml`) that protected packages were actually compiled as `CompiledPythonModule` rather than included as uncompiled bytecode/data files.
  - Non-interactive CI/agent runs on Windows may block on Nuitka's MinGW64/dependencywalker download prompt unless `--assume-yes-for-downloads` is passed (online build) or `NUITKA_CACHE_DIR` is pre-populated (offline build).
  - Dynamic plugin loading, `pkgutil`, ORM lazy mappers, and data files loaded via `Path(__file__)` require explicit `--include-package`, `--include-module`, or `--include-data-dir`/`--include-data-files` verification.

### Route C — Existing PyInstaller Pipeline + Native-Compiled Core
- **Best fit**: Project already ships reliably with **PyInstaller** (`.spec` file, hooks, installer integration) and changing packagers would introduce unnecessary deployment churn.
- **Mechanism**: Compile the sensitive core modules **first** into native `.pyd`/`.so` extensions (via Cython or Nuitka `--module`), remove raw core `.py` files from the staging tree, and let PyInstaller bundle the outer Python application + compiled native extensions.
- **Critical Boundary**: Standard PyInstaller archives (`PYZ` / `.pyc` inside one-folder or one-file bundles) are **packaging mechanisms, not strong source protection**—tools readily extract and decompile bundled `.pyc` bytecode. PyInstaller discontinued `--key` bytecode encryption (`tinyaes`) in PyInstaller 6.0 precisely because embedded keys in the binary offered only trivial obfuscation. Always pair PyInstaller with real native compilation of protected modules.

### Route D — Additional Obfuscation (e.g., PyArmor) — Conditional Only
- **Best fit**: Only when there is a documented requirement not met by Routes A–C (for example, encrypting outer orchestration scripts that cannot be compiled cleanly by Cython/Nuitka), verified compatibility with the target Python version/OS, and acceptable startup/runtime overhead.
- **Constraints**:
  - Check license tier restrictions before proposing: PyArmor Free has code-object size/feature limits and commercial/CI/BCC/RFT tier distinctions.
  - Never silently depend on paid features, purchase licenses, or alter tool licensing without explicit user approval.
  - Verify `pyarmor_runtime` native library bundling and tracebacks/debugging behavior under offline execution.

## 4. Python Dynamic-Feature & Packaging Hazard Checklist

Inspect every candidate module for these patterns before compiling:
1. **Dynamic Imports & Plugins**: `importlib.import_module`, `__import__`, `pkgutil.iter_modules`, ` importlib.metadata.entry_points`. Static compilers cannot discover string-computed module names without explicit include declarations.
2. **Framework Introspection**: FastAPI endpoint signature inspection, Pydantic model field annotations, Typer CLI type hints, SQLAlchemy declarative models. Keeping route/schema definitions in thin outer Python wrappers while compiling pure domain/math engines (`Route A`) avoids annotation-erasure regressions.
3. **Filesystem & Resource Paths**: Replace fragile `os.getcwd()` assumptions and raw `../../web/dist` relative paths with explicit environment/config overrides (`APP_STATIC_DIR`, `APP_DATA_DIR`) plus `importlib.resources` or frozen-aware bundle root resolution (`sys._MEIPASS` / executable directory).
4. **Windows Multiprocessing & Subprocesses**: Standalone executables spawning worker processes on Windows require `multiprocessing.freeze_support()` at entrypoint startup; avoid invoking `"python"` on `PATH` from subprocesses when shipping standalone bundles.
5. **Serialization**: `pickle` payloads hardcode module/class import paths; renaming or moving core classes into compiled submodules can break reading existing customer `.pkl` files unless compatibility aliases or format migrations are tested.

## 5. Protecting Rules, Models, and Data Assets (Goal G4)

- **Plain JSON/YAML/CSV Rule Tables or Calibration Constants**: If small and static, compile them into native C constants/structures inside a compiled core module rather than leaving `rules.json` readable on disk.
- **Large Weights / Local Models / Databases**: Measure startup/memory cost before embedding. When deployed on customer-controlled hardware, encrypting model files with a key stored inside the same local binary only deters casual file browsing—state clearly that runtime memory/key extraction by a local admin remains possible.

## 6. Verified Official Documentation & Tool Baseline

- **Verification Date**: `2026-11-11`
- **Verified Local Toolchain Baseline (Host Validation Venv)**:
  - `Python`: `3.12.10` (`MSC v.1943 64 bit (AMD64)`)
  - `Cython`: `3.3.1`
  - `Nuitka`: `4.3.5`
  - `PyInstaller`: `6.22.3`
  - `cryptography`: `50.0.2`
  - `Vite` (inspected local frontend baseline): `8.3.0`

| Topic | Official Reference URL | Key Verified Engineering Fact (Non-Marketing) |
| :--- | :--- | :--- |
| PyInstaller operating modes & Cython pairing | https://pyinstaller.org/en/stable/operating-mode.html | PyInstaller bundles `.pyc` bytecode into `PYZ`/executable archives for deployment; official docs recommend compiling sensitive modules to C/native extensions via Cython rather than relying on archive bundling for code hiding. |
| Nuitka User Manual (`--module`, `--standalone`, `--include-*`, `--report`) | https://nuitka.net/user-documentation/user-manual.html | Translates Python modules to C via libpython/Scons; `--module` builds binary extension modules (`.pyd`/`.so`), `--standalone` produces self-contained `.dist` folders, and `--report` emits XML proof of compiled vs bytecode modules. |
| Cython Source Files & Compilation | https://cython.readthedocs.io/en/stable/src/userguide/source_files_and_compilation.html | Compiles `.py` or `.pyx` into `.c`/`.cpp` and links platform/ABI-specific native extensions via `cythonize` and a host C compiler; intermediate `.c` files contain readable generated metadata/strings if accidentally shipped. |
| PyArmor Project Overview | https://github.com/dashingsoft/pyarmor | Obfuscates Python code objects paired with a native `pyarmor_runtime` extension; v8/v9 architecture separates build-time obfuscation from target runtime execution and gates RFT/BCC/CI capabilities by license tier. |
| PyArmor Official Q&A | https://pyarmor.readthedocs.io/en/stable/questions.html | Documents platform-specific runtime library requirements, packaging integration order (obfuscate first, then bundle `pyarmor_runtime`), and size/license constraints. |
| OWASP Web Frontend Security Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Web_Frontend_Security_Cheat_Sheet.html | Client-side JavaScript and browser storage cannot keep secrets or enforce trusted access control; authorization and sensitive logic belong on trusted server boundaries, and third-party scripts/CDNs expand supply-chain and offline-failure surfaces. |
| Vite `build.sourcemap` Option | https://vite.dev/config/build-options.html#build-sourcemap | Defaults to `false` in production, but setting `true`, `'inline'`, or `'hidden'` emits reconstructible original frontend source (`'hidden'` omits the comment in `.js` while still writing `.map` files onto disk that leak if packaged!). |
| PyCA `cryptography` Ed25519 | https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/ | Provides standard RFC 8032 `Ed25519PrivateKey.sign` and `Ed25519PublicKey.verify` (64-byte signatures, 32-byte raw keys) without custom cryptographic primitives. |
