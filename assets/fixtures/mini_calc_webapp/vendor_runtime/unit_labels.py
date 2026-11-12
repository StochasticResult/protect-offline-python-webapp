"""Synthetic third-party/vendor runtime helper kept as allowed plain Python."""

UNIT_LABELS = {
    "hz": "Hz",
    "db": "dBc",
    "rms": "Vrms",
}


def format_unit(key: str) -> str:
    return UNIT_LABELS.get(key, key)
