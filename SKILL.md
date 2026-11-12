---
name: protect-offline-python-webapp
description: Audit, compile, package, and verify offline Python backend plus JavaScript web frontend applications to raise the cost of reading, copying, or modifying core implementations while preserving runtime behavior. Use when asked to protect or harden an offline Python and JS web app, compile core Python modules into native binaries, inspect release bundles for source or secret leaks, build protected offline delivery packages, or validate offline distribution. Do not trigger for routine feature development, bug fixes, or ordinary UI updates.
---

# Protect Offline Python Webapp

Review an existing Python backend + JavaScript frontend application, select an evidence-based native compilation and packaging route without breaking business semantics, prevent accidental source or secret leakage in deliverables, and verify offline execution within explicit trust and network boundaries.

## Operating Modes & Authorization

Select the mode matching the user's request before touching any files:

1. **Audit (`audit`)**: Read-only reconnaissance, trust-boundary analysis, protected-asset inventory, and route recommendation. Modify zero project files. Default to `audit` when the user's scope is ambiguous, or when only creating/testing this skill.
2. **Implement & Build (`implement`)**: When the user explicitly authorizes protection changes or a protected build, proceed directly from audit through reversible build wiring, isolated compilation, artifact leak inspection, and offline verification without asking confirmation at every routine step.
3. **Verify (`verify`)**: Inspect an existing build directory, archive, or installer and execute isolated runtime and offline checks, reporting concrete evidence.

**Permission & Scope Guardrails:**
- Never treat read-only inspection or skill setup as authorization to alter production repositories, enable license enforcement, publish releases, or replace live deployments.
- Keep developer source trees intact: apply protection in dedicated build/staging outputs rather than deleting or overwriting original `.py`/`.ts`/`.js` sources or touching unrelated uncommitted changes.
- Discover facts from project files first (`AGENTS.md`, README, entrypoints, Python/JS lockfiles, bundler configs, packaging scripts, CI, tests, deployment docs). Ask **at most 3** targeted questions at once, and only when unresolved facts materially change target OS/ABI, deployment trust boundary, or licensing behavior.

## Offline & Trust-Boundary Rules

1. **Separate Runtime Offline from Build Offline**:
   - Record **Runtime Internet Policy** (application runs with zero public internet access) separately from **Build Environment Connectivity** (whether compilers/toolchains/wheels may be fetched during build or must come from an offline cache/wheelhouse). Never conflate the two.
2. **Preserve Required Local & Intranet Links**:
   - Offline operation permits required `localhost`, LAN, internal database, NAS, local LLM/model server, or hardware/instrument connections. Never equate "offline" with disabling all network interfaces.
3. **State Honest Security Boundaries**:
   - Distinguish four separate goals: (a) reducing direct source exposure, (b) raising reverse-engineering/modification cost of core logic, (c) restricting unauthorized execution/copying, and (d) protecting rule tables, parameters, models, and sensitive data assets.
   - Browser-delivered JS, Wasm, and static assets are always inspectable by end users.
   - If the customer controls the host running Python, a local backend service is **not** trusted isolation against that customer. Only treat a backend server as an isolation boundary when operated by the provider or a trusted administrator and the threat actor lacks OS admin rights, program file read access, and debugging privileges.
   - Native compilation, symbol stripping, obfuscation, and bundling raise analysis cost; never claim "irreversible", "AI-unbreakable", "permanent secrecy", or unmeasured crack-time multipliers.

## Core Workflow

### Step 1: Reconnaissance & Protected-Asset Inventory
1. Run read-only reconnaissance with `scripts/offline_protect_tool.py audit --project-root <path> --output <report.json>` and inspect key configs (`AGENTS.md`, entrypoints, `pyproject.toml`/`requirements*.txt`, `package.json`, bundler config, existing release scripts).
2. Record 8 factual dimensions:
   - Git status and pre-existing uncommitted work.
   - Python entrypoints, core calculation/domain modules, dynamic imports (`importlib`, `__import__`, plugins, reflection), serialization (`pickle`), asset loading, and native C/Rust dependencies.
   - Frontend build pipeline, static assets, source maps, Web Workers, Wasm, fonts, and any external CDN/telemetry URLs.
   - Backend host control model, client access pattern, and allowed network destinations (`127.0.0.1`, specific LAN subnets/ports).
   - Target OS, CPU architecture, Python ABI, and delivery format (never assume the current agent host OS is the target OS).
   - Runtime filesystem layout: install root (potentially read-only) vs writable user data, config, logs, DB, and exports.
   - Existing licensing, update, or machine-binding logic to preserve.
   - Existing test suites, sanitized sample inputs, numerical tolerances, and latency/size budgets.
3. Produce an explicit **Protected Module & Asset Inventory**: for every item, state its business value, current exposure form, planned protection treatment, and acceptance test. Propose minimal interface-preserving splits only when core logic is tangled with framework glue.

### Step 2: Route Selection
Read [references/decision-rules.md](references/decision-rules.md) and pick **one primary route** supported by project evidence:
- **Route A (Concentrated Core, Stable Interfaces)**: Compile core modules into native extensions (`.pyd`/`.so`) via Cython or Nuitka `--module`; keep outer web framework glue and existing packaging intact.
- **Route B (Dispersed Python Logic, Minimal Refactoring)**: Compile via Nuitka standalone/whole-application mode and verify protected packages are compiled into binaries rather than copied as bytecode/source.
- **Route C (Existing PyInstaller Pipeline)**: Retain PyInstaller for distribution if already working, **combined** with native-compiled core modules. Never describe plain PyInstaller `.pyc`/PYZ bundling alone as strong source protection.
- **Route D (Extra Obfuscation, e.g., PyArmor)**: Evaluate only when explicit requirements, runtime compatibility proof, and license terms justify it. Never default to paid tiers or purchase/alter licenses autonomously.

Do **not** stack every tool by default, replace web/frontend frameworks or databases, add Electron/desktop shells just for protection, or rewrite backend algorithms into browser Wasm for secrecy.

### Step 3: Baseline Capture
Before changing build outputs, run existing functional tests covering normal, boundary, and invalid/error inputs. Record baseline outputs, numerical tolerances, startup latency, critical-request latency, and package size so pre-existing bugs are neither masked nor misattributed.

### Step 4: Isolated Build & Fail-Closed Compilation
Read [references/build-and-offline-validation.md](references/build-and-offline-validation.md) before building.
1. Pin exact compiler/packager versions inside an isolated virtual environment without opportunistically upgrading unrelated runtime dependencies. Verify CLI flags against installed `--help` and official docs for that version.
2. Build Frontend production bundles using the project's existing bundler with production source maps disabled (or stripped prior to staging) and all required JS, CSS, fonts, icons, chart libraries, and templates vendored locally. Never rely on right-click disabling, DevTools blocking, or hidden UI buttons as security controls.
3. Compile declared protected Python modules in dedicated build/staging directories (`scripts/offline_protect_tool.py build --manifest <manifest.json>` or the project's verified build script).
4. **Fail-Closed Rule (Mandatory)**: If **any** declared protected module fails native compilation or is missing from compiled output, the build and protection acceptance **must fail (`FAIL`, non-zero exit)**. Never silently fall back to shipping raw `.py`, plain `.pyc`, or unprotected fallback implementations while reporting success. If lowering protection scope is an option, stop and present the cause, exact exposed surface, and alternatives for user decision.
5. Prefer auditable directory distributions first unless single-file delivery is explicitly required (single-file extraction archives are not an extra security boundary).

### Step 5: Optional Offline Signed Licensing (Default OFF)
Preserve any existing authorization logic. **Do not** add license checks, expiry, machine binding, telemetry, or kill-switches unless the user explicitly asks for them.
- Only when explicitly requested, read [references/licensing.md](references/licensing.md) and enforce Ed25519 public-key verification inside the compiled core execution path (testing direct Python/API calls that bypass the web UI, using disposable test keys outside repo/release paths, and failing non-destructively with respect to user data).

### Step 6: Artifact Leak Inspection & Offline Acceptance
1. Run `scripts/offline_protect_tool.py inspect --artifact <dir-or-archive> --manifest <manifest.json>` across real delivery directories and internal archives:
   - Reject raw `.py`/`.pyx`/`.pxd`, plain `.pyc` copies of protected modules, generated `.c`/`.cpp`, `.map` files, inline `sourceMappingURL`, HTML source-leaking comments, unbundled sensitive JSON rule/coefficient tables, test secrets, and private keys.
   - Redact suspected secret values in logs (report file path, line, and rule ID only) and honor explicit allowlists for required third-party runtime files and open-source license notices.
   - Mark any uninspected archive format or opaque container as `UNVERIFIED`—never assume uninspected containers are clean.
2. Run `scripts/offline_protect_tool.py verify-offline --artifact <dir> --manifest <manifest.json>` (plus real browser checks where available):
   - Prove compiled module provenance at runtime (`__file__`, loader type, path inside artifact—not dev checkout) from a clean working directory, including paths with spaces and non-ASCII/Unicode characters and read-only install roots with separate writable data directories where applicable.
   - Block unapproved external internet sockets without altering host firewall rules or system clock, verify local UI/API/import-export flows and error/port-conflict cleanup, compare results against baseline within justified tolerances, and distinguish **process-level / browser-level offline checks** from **full physical airgap / clean target-machine verification** (`UNVERIFIED` if not executed on an airgapped target OS).
   - Distinguish "repeatable build procedure" from "byte-for-byte reproducible build" unless the latter is empirically verified across independent builds.

## Resource Map

- [references/decision-rules.md](references/decision-rules.md): Threat/trust boundaries, Route A–D selection matrix, Python dynamic-feature hazards, sensitive data handling, and verified official documentation links.
- [references/build-and-offline-validation.md](references/build-and-offline-validation.md): Runtime-offline vs build-offline matrix, manifest schema (`protection-manifest.json`), path-safe staging/rollback, runtime provenance checks, leak rules, and offline acceptance criteria.
- [references/licensing.md](references/licensing.md): Opt-in offline Ed25519 licensing design, canonical payload signing, core-entry enforcement, bypass tests, and offline revocation/fingerprint limits.
- `scripts/offline_protect_tool.py`: CLI helper (`audit`, `build`, `inspect`, `verify-offline`, `clean`, `license-selftest`) with `--dry-run`, secret redaction, path containment guards, and `PASS / FAIL / UNVERIFIED / NOT_APPLICABLE` reporting.
- `assets/fixtures/mini_calc_webapp/`: Synthetic offline Python HTTP + vanilla JS + numerical core fixture and test suite for end-to-end validation.
