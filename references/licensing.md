# Optional Offline Signed Licensing (Default OFF)

Read this reference **only** when the user explicitly requests anti-piracy controls, customer/site licensing, expiration dates, machine binding, or feature entitlements, **or** when auditing/preserving an application's existing license mechanism.

> **Default Rule**: When the user has not asked for licensing restrictions, **do not** add license checks, expiration bombs, hardware fingerprinting, telemetry, or remote kill-switches.

## 1. Cryptographic & Architectural Design

1. **Standard Asymmetric Signatures Only (Ed25519)**:
   - Use RFC 8032 **Ed25519** from a mature library such as PyCA `cryptography` (`cryptography.hazmat.primitives.asymmetric.ed25519`). Never invent custom hashes, XOR/AES shared-secret license keys, or homegrown math.
   - **Strict Key Separation**:
     - **Issuer Private Key (`Ed25519PrivateKey`)**: Generated and stored strictly offline in the software provider's signing environment. Never place production private keys inside application repositories, CI logs, skill directories, or customer deliverables.
     - **Embedded Verifier Public Key (`Ed25519PublicKey`)**: Embed the 32-byte public key inside the compiled native core module (not solely in an editable `.env` or outer `.py` config file).
2. **File-Based Offline Provisioning**:
   - Deliver licenses as portable signed files (e.g., `license.json` imported via local file path or offline admin upload) requiring zero internet calls at startup or runtime.

## 2. Canonical Versioned License Envelope

Guarantee that **the exact bytes verified by Ed25519 are the exact bytes parsed by business logic**—never verify one JSON representation while parsing another unverified dictionary field.

### Recommended Envelope Format

```json
{
  "payload_b64": "eyJzY2hlbWFfdmVyc2lvbiI6MSwibGljZW5zZV9pZCI6IkxJQy1URVNULTAwMSIsInByb2R1Y3QiOiJtaW5pLWNhbGMtd2ViYXBwIiwic3ViamVjdCI6IkxhYi1BIiwiaXNzdWVkX2F0IjoiMjAyNi0xMS0xMVQwMDowMDowMFoiLCJub3RfYmVmb3JlIjoiMjAyNi0xMS0xMVQwMDowMDowMFoiLCJleHBpcmVzX2F0IjoiMjAyNy0xMS0xMVQwMDowMDowMFoiLCJmZWF0dXJlcyI6WyJjb3JlLWNhbGMiXX0=",
  "signature_b64": "<base64url-64-byte-ed25519-signature>"
}
```

### Verification Sequence (Fail-Closed & Unambiguous)

1. Reject inputs exceeding a small byte cap (e.g., `16 KiB`) or containing non-UTF-8 bytes.
2. Parse outer JSON strictly as a `dict` containing **only** string fields `payload_b64` and `signature_b64` (reject duplicate keys or ambiguous types via `parse_constant` denying `NaN`/`Infinity`).
3. Base64url-decode `payload_bytes` and `signature_bytes` (`len(signature_bytes) == 64`).
4. Call `public_key.verify(signature_bytes, payload_bytes)` **before** inspecting payload contents. Any `InvalidSignature` fails immediately.
5. Parse `payload_bytes.decode("utf-8")` as UTF-8 JSON and validate exact schema fields:
   - `schema_version == 1` (exact integer check `type(v) is int`, not `bool`!)
   - `product` matches expected application identifier
   - `not_before` and `expires_at` parsed as explicit UTC ISO-8601 timestamps (`Z` / `+00:00`) compared against an injectable UTC clock (`now_utc`, defaulting to `datetime.now(timezone.utc)`)
   - Required `features` (e.g., `"core-calc"`) present in `features` list
   - Optional `machine_binding` compared only if the product explicitly specifies binding

Keep payload fields minimal—include only fields actively enforced by the product.

## 3. Enforce Inside Compiled Core Entrypoints (Not UI or Outer Glue)

A common implementation flaw is checking `is_licensed == True` only in JavaScript UI components or an outer FastAPI route while leaving the compiled `.pyd`/`.so` calculation function unrestricted:

- **Wrong**: Frontend hides the "Calculate" button, or `app_server.py` checks `check_license()` in plain Python before calling `spectrum_core.analyze(data)`. Anyone on the machine can edit `app_server.py` or run `python -c "import core.spectrum_core as c; print(c.analyze(...))"`.
- **Right**: Place signature and entitlement verification inside the compiled native module (`core/spectrum_core`) so core computation entrypoints (`analyze_spectrum`, `export_calibrated_report`) verify an active signed license token/envelope directly before executing protected math.

## 4. Mandatory Test Matrix (When Licensing Branch Is Enabled)

Use **disposable ephemeral Ed25519 test keypairs** generated in a temporary directory outside the repository and build output, plus an **injectable test clock** (never change the host OS clock!):

1. **Default Disabled Check**: With licensing disabled (default), core operations succeed without any license file.
2. **Valid Signed Test License**: Succeeds via both HTTP API and direct Python core import.
3. **Missing License File**: Fails cleanly with structured error code (`403`/`PermissionError`).
4. **Invalid Signature** (signed by a different keypair or flipped signature bit): Rejected before payload parsing.
5. **Tampered Payload** (`expires_at` or `features` modified inside `payload_b64` while keeping original signature): Rejected by `Ed25519PublicKey.verify`.
6. **Malformed Envelope / Ambiguous JSON** (truncated JSON, non-dict payload, wrong `schema_version`, missing `expires_at`, boolean `True` passed as `schema_version: true`): Rejected cleanly without uncaught crash.
7. **Expired / Not-Yet-Valid / Wrong Feature Scope**: Tested via injected `now_utc` timestamp and mismatched `features` list -> Rejected cleanly.
8. **Direct Core Bypass Attempt**: Import the compiled `.pyd`/`.so` directly from Python bypassing the web UI and HTTP server without a valid license -> Rejected by the compiled core guard.
9. **Non-Destructive Failure Behavior**: Verify pre-existing user data/workspace files in `APP_DATA_DIR` remain 100% intact and readable after any license rejection—never delete, corrupt, or encrypt user data on license failure.

## 5. Honest Operational & Security Limits

State these limits clearly whenever proposing or delivering offline licensing:

- **Anti-Forgery vs. Local Binary Patching**: Ed25519 prevents forging a new license without the issuer's private key, but a skilled adversary with root/admin control over the local machine can still debug or binary-patch the compiled `.pyd`/`.so`/executable to skip the verification jump.
- **No Automatic Offline Revocation**: A completely airgapped machine cannot learn that a previously issued valid license was later revoked until a signed revocation list or software update is manually imported; short validity windows mitigate exposure at the cost of renewal friction.
- **Clock & Machine Fingerprint Fragility**: Ordinary OS clocks can be rolled back by a local admin, and user-space machine identifiers (MAC addresses, hostname, disk serials, container/VM IDs) can both be spoofed by attackers and legitimately change during NIC replacement, OS upgrades, or VM migration. Never market software-only fingerprints or local clocks as tamper-proof hardware anchors.
