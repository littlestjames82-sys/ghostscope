"""Pack validation, mirroring `ghostslice check` semantics:
hashes and sliced-token totals (GhostSlice token method) must
match what is on disk in files/."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .scanner import language_for
from .tokens import estimate_tokens


def validate_pack(bundle: str | Path) -> dict:
    bundle = Path(bundle)
    errors: list[str] = []
    mpath = bundle / "manifest.json"
    try:
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"ok": False, "errors": [f"manifest.json unreadable: {exc}"],
                "files_checked": 0}
    checked = 0
    total_sliced = 0
    for entry in manifest.get("files", []):
        path = entry["path"]
        if entry.get("mode") == "exclude":
            if entry.get("sliced_tokens") != 0:
                errors.append(f"{path}: excluded but sliced_tokens != 0")
            continue
        dest = bundle / "files" / path
        text = dest.read_bytes().decode("utf-8", errors="replace") \
            if dest.is_file() else ""
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if text and digest != entry.get("sha256"):
            errors.append(f"{path}: sha256 mismatch")
        recomputed = estimate_tokens(text, language_for(path))
        if recomputed != entry.get("sliced_tokens"):
            errors.append(f"{path}: sliced_tokens {entry.get('sliced_tokens')} "
                          f"!= recomputed {recomputed}")
        total_sliced += recomputed
        checked += 1
    if total_sliced != manifest.get("total_sliced_tokens"):
        errors.append(f"total_sliced_tokens {manifest.get('total_sliced_tokens')} "
                      f"!= recomputed {total_sliced}")
    return {"ok": not errors, "errors": errors, "files_checked": checked,
            "total_sliced_tokens": total_sliced,
            "total_original_tokens": manifest.get("total_original_tokens", 0)}
