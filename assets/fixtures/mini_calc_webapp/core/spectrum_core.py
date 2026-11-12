"""Synthetic core harmonic & calibration calculation engine.

Designed for testing native compilation (.pyd/.so), runtime provenance checks,
numerical parity, and optional core-entrypoint Ed25519 offline license guards.
Default mode leaves licensing completely disabled (REQUIRE_LICENSE_DEFAULT = False).
"""

from __future__ import annotations

import base64
import json
import math
import os
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

PRODUCT_ID = "mini-calc-webapp"
REQUIRE_LICENSE_DEFAULT = False
EMBEDDED_LICENSE_PUBKEY_HEX = ""

# Compiled internal calibration polynomial coefficients (replaces shipping raw JSON rules)
_MODE_POLYNOMIALS: dict[str, tuple[float, float, float]] = {
    "standard": (1.0025, -0.00042, 0.000015),
    "precision": (1.0008, -0.00011, 0.000004),
}


class SpectrumInputError(ValueError):
    """Raised when input samples or parameters violate domain constraints."""


class LicenseVerificationError(PermissionError):
    """Raised when opt-in core license enforcement rejects an operation."""


def is_licensing_enabled() -> bool:
    return bool(REQUIRE_LICENSE_DEFAULT or EMBEDDED_LICENSE_PUBKEY_HEX)


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 16384:
        raise LicenseVerificationError("Invalid base64url field in license envelope.")
    padding = "=" * ((4 - (len(value) % 4)) % 4)
    try:
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except Exception as exc:
        raise LicenseVerificationError("Malformed base64url encoding in license envelope.") from exc


def _parse_utc_iso(ts: Any, field_name: str) -> datetime:
    if not isinstance(ts, str) or not ts.strip():
        raise LicenseVerificationError(f"Missing or non-string timestamp '{field_name}'.")
    normalized = ts.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise LicenseVerificationError(f"Invalid ISO-8601 timestamp in '{field_name}'.") from exc
    if dt.tzinfo is None:
        raise LicenseVerificationError(f"Timestamp '{field_name}' must include explicit UTC offset.")
    return dt.astimezone(timezone.utc)


def _reject_constants(val: str) -> Any:
    raise LicenseVerificationError(f"Forbidden JSON constant '{val}' in license data.")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise LicenseVerificationError(f"Duplicate JSON key '{key}' in license data.")
        out[key] = value
    return out


def verify_license_envelope(
    raw_envelope: str | bytes | Mapping[str, Any] | None,
    required_feature: str = "core-calc",
    now_utc: datetime | None = None,
    pubkey_hex_override: str | None = None,
) -> dict[str, Any]:
    """Verify an Ed25519-signed license envelope before parsing business claims."""
    pubkey_hex = (pubkey_hex_override if pubkey_hex_override is not None else EMBEDDED_LICENSE_PUBKEY_HEX).strip()
    if not pubkey_hex:
        raise LicenseVerificationError("Licensing is enabled, but no verifier public key is configured.")

    if raw_envelope is None:
        env_path = os.environ.get("MINI_CALC_LICENSE_FILE", "").strip()
        if env_path:
            try:
                with open(env_path, "rb") as fh:
                    raw_envelope = fh.read(16385)
            except OSError as exc:
                raise LicenseVerificationError("Configured license file could not be read.") from exc
        else:
            raise LicenseVerificationError("Missing required signed license envelope.")

    if isinstance(raw_envelope, (str, bytes)):
        raw_bytes = raw_envelope.encode("utf-8") if isinstance(raw_envelope, str) else raw_envelope
        if len(raw_bytes) > 16384 or len(raw_bytes) == 0:
            raise LicenseVerificationError("License envelope size out of bounds.")
        try:
            envelope = json.loads(
                raw_bytes.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_constants,
            )
        except UnicodeDecodeError as exc:
            raise LicenseVerificationError("License envelope is not valid UTF-8.") from exc
        except json.JSONDecodeError as exc:
            raise LicenseVerificationError("License envelope is not valid JSON.") from exc
    elif isinstance(raw_envelope, Mapping):
        envelope = dict(raw_envelope)
    else:
        raise LicenseVerificationError("Unsupported license envelope type.")

    if not isinstance(envelope, dict) or set(envelope.keys()) != {"payload_b64", "signature_b64"}:
        raise LicenseVerificationError("Envelope must contain exactly 'payload_b64' and 'signature_b64'.")

    payload_bytes = _b64url_decode(envelope["payload_b64"])
    signature_bytes = _b64url_decode(envelope["signature_b64"])
    if len(signature_bytes) != 64:
        raise LicenseVerificationError("Ed25519 signature must be exactly 64 bytes.")

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pub_bytes = bytes.fromhex(pubkey_hex)
        if len(pub_bytes) != 32:
            raise LicenseVerificationError("Verifier Ed25519 public key must be 32 bytes.")
        pubkey = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pubkey.verify(signature_bytes, payload_bytes)
    except InvalidSignature as exc:
        raise LicenseVerificationError("License signature verification failed.") from exc
    except LicenseVerificationError:
        raise
    except Exception as exc:
        raise LicenseVerificationError(f"Cryptographic verification error: {type(exc).__name__}") from exc

    try:
        payload = json.loads(
            payload_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constants,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LicenseVerificationError("Signed payload is not valid UTF-8 JSON.") from exc

    if not isinstance(payload, dict):
        raise LicenseVerificationError("Signed license payload must be a JSON object.")
    if type(payload.get("schema_version")) is not int or payload["schema_version"] != 1:
        raise LicenseVerificationError("Unsupported or invalid license schema_version.")
    if payload.get("product") != PRODUCT_ID:
        raise LicenseVerificationError("License product identifier mismatch.")

    features = payload.get("features")
    if not isinstance(features, list) or not all(isinstance(item, str) for item in features):
        raise LicenseVerificationError("License 'features' field must be a list of strings.")
    if required_feature not in features:
        raise LicenseVerificationError(f"License does not grant required feature '{required_feature}'.")

    not_before = _parse_utc_iso(payload.get("not_before"), "not_before")
    expires_at = _parse_utc_iso(payload.get("expires_at"), "expires_at")
    if expires_at <= not_before:
        raise LicenseVerificationError("License expiry must be after not_before.")

    effective_now = now_utc.astimezone(timezone.utc) if now_utc is not None else datetime.now(timezone.utc)
    if effective_now < not_before:
        raise LicenseVerificationError("License is not yet valid.")
    if effective_now >= expires_at:
        raise LicenseVerificationError("License has expired.")

    return payload


def analyze_harmonics(
    samples: Sequence[float],
    sample_rate_hz: float,
    mode: str = "standard",
    license_envelope: str | bytes | Mapping[str, Any] | None = None,
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    """Compute calibrated RMS, fundamental bin, and THD ratio for a real-valued window."""
    if is_licensing_enabled():
        verify_license_envelope(
            license_envelope,
            required_feature="core-calc",
            now_utc=now_utc,
        )

    if isinstance(sample_rate_hz, bool) or not isinstance(sample_rate_hz, (int, float)):
        raise SpectrumInputError("sample_rate_hz must be a finite positive number.")
    sr = float(sample_rate_hz)
    if not math.isfinite(sr) or sr <= 0.0:
        raise SpectrumInputError("sample_rate_hz must be strictly positive and finite.")

    if mode not in _MODE_POLYNOMIALS:
        raise SpectrumInputError(f"Unsupported calibration mode '{mode}'.")

    if not isinstance(samples, Sequence) or isinstance(samples, (str, bytes)):
        raise SpectrumInputError("samples must be a sequence of numbers.")
    n = len(samples)
    if n < 4 or n > 4096:
        raise SpectrumInputError("samples length must be between 4 and 4096.")

    clean: list[float] = []
    for idx, raw in enumerate(samples):
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise SpectrumInputError(f"Sample at index {idx} is not numeric.")
        val = float(raw)
        if not math.isfinite(val):
            raise SpectrumInputError(f"Sample at index {idx} must be finite.")
        clean.append(val)

    mean_val = sum(clean) / n
    centered = [x - mean_val for x in clean]
    raw_rms = math.sqrt(sum(x * x for x in centered) / n)

    c0, c1, c2 = _MODE_POLYNOMIALS[mode]
    calibrated_rms = raw_rms * (c0 + c1 * raw_rms + c2 * (raw_rms * raw_rms))

    half_bins = n // 2
    magnitudes: list[float] = []
    for k in range(1, half_bins + 1):
        re = 0.0
        im = 0.0
        angle_step = -2.0 * math.pi * k / n
        for idx, x in enumerate(centered):
            theta = angle_step * idx
            re += x * math.cos(theta)
            im += x * math.sin(theta)
        mag = (2.0 / n) * math.hypot(re, im)
        magnitudes.append(mag)

    peak_mag = max(magnitudes) if magnitudes else 0.0
    if peak_mag <= 1e-15:
        fundamental_hz = 0.0
        thd_percent = 0.0
        fundamental_bin = 0
    else:
        fundamental_idx = magnitudes.index(peak_mag)
        fundamental_bin = fundamental_idx + 1
        fundamental_hz = (fundamental_bin * sr) / n
        harmonic_power = 0.0
        for harmonic_mult in (2, 3, 4, 5):
            h_bin = fundamental_bin * harmonic_mult
            if h_bin <= half_bins:
                h_mag = magnitudes[h_bin - 1]
                harmonic_power += h_mag * h_mag
        thd_percent = 100.0 * math.sqrt(harmonic_power) / peak_mag

    return {
        "sample_count": n,
        "sample_rate_hz": round(sr, 6),
        "mode": mode,
        "dc_offset": round(mean_val, 9),
        "raw_rms": round(raw_rms, 9),
        "calibrated_rms": round(calibrated_rms, 9),
        "fundamental_bin": fundamental_bin,
        "fundamental_hz": round(fundamental_hz, 6),
        "thd_percent": round(thd_percent, 6),
    }
