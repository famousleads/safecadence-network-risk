"""Custom compliance framework loader.

Lets users define their own internal/industry frameworks in YAML and have
them appear alongside the built-in NIST/CIS/PCI/HIPAA/SOC2/NIS2/FedRAMP/CMMC
libraries in the compliance reports.

YAML schema:
    frameworks:
      - id: "ACME-INTERNAL"
        name: "Acme Internal Security Standard"
        category: "Internal policy"
        families: ["Identity", "Network", "Data"]
        controls:
          - id: "ACME-IAM-01"
            title: "MFA on all admin"
            family: "Identity"
            purpose: "Prevent credential theft from leading to account takeover."

The merged dict has the same shape as ``_COMPLIANCE_LIBRARY`` in
``sections.py`` — each control is normalized to the
``(control_id, title, family, purpose)`` tuple.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


DEFAULT_PATH = "~/.safecadence/custom_frameworks.yaml"


def _default_path() -> Path:
    return Path(os.path.expanduser(DEFAULT_PATH))


def validate_framework(definition: dict) -> list[str]:
    """Return a list of validation errors for a single framework dict.

    Empty list ⇒ definition is well-formed.
    """
    errors: list[str] = []
    if not isinstance(definition, dict):
        return ["framework must be a mapping/object"]

    fid = definition.get("id")
    if not fid or not isinstance(fid, str):
        errors.append("framework.id must be a non-empty string")

    name = definition.get("name")
    if not name or not isinstance(name, str):
        errors.append("framework.name must be a non-empty string")

    category = definition.get("category")
    if not category or not isinstance(category, str):
        errors.append("framework.category must be a non-empty string")

    families = definition.get("families")
    if not isinstance(families, list) or not all(isinstance(f, str) for f in families):
        errors.append("framework.families must be a list of strings")

    controls = definition.get("controls")
    if not isinstance(controls, list) or not controls:
        errors.append("framework.controls must be a non-empty list")
        return errors

    for i, c in enumerate(controls):
        if not isinstance(c, dict):
            errors.append(f"controls[{i}] must be a mapping")
            continue
        for key in ("id", "title", "family", "purpose"):
            v = c.get(key)
            if not v or not isinstance(v, str):
                errors.append(f"controls[{i}].{key} must be a non-empty string")
    return errors


def _normalize_framework(definition: dict) -> tuple[str, dict]:
    """Convert a YAML framework definition into the internal library shape.

    Returns ``(key, value)`` where ``value`` matches the existing
    ``_COMPLIANCE_LIBRARY`` entries (controls as 4-tuples).
    """
    key = str(definition.get("id"))
    controls = []
    for c in definition.get("controls") or []:
        controls.append((
            str(c.get("id")),
            str(c.get("title")),
            str(c.get("family")),
            str(c.get("purpose")),
        ))
    value = {
        "name": str(definition.get("name")),
        "category": str(definition.get("category")),
        "families": list(definition.get("families") or []),
        "controls": controls,
        "custom": True,
    }
    return key, value


def load_custom_frameworks(path: str | None = None) -> dict[str, dict]:
    """Load and validate custom frameworks from YAML.

    Returns an empty dict if no file is present, PyYAML isn't installed,
    or the file is malformed. Invalid frameworks within a valid file are
    skipped (silently) — call :func:`validate_framework` on individual
    definitions if you want hard errors.
    """
    p = Path(path) if path else _default_path()
    if not p.exists():
        return {}

    try:
        import yaml  # PyYAML — a hard dep of the project
    except Exception:
        return {}

    try:
        text = p.read_text(encoding="utf-8")
        doc = yaml.safe_load(text) or {}
    except Exception:
        return {}

    frameworks = doc.get("frameworks") if isinstance(doc, dict) else None
    if not isinstance(frameworks, list):
        return {}

    out: dict[str, dict] = {}
    for fw in frameworks:
        errs = validate_framework(fw)
        if errs:
            continue
        key, value = _normalize_framework(fw)
        if key:
            out[key] = value
    return out


__all__ = [
    "DEFAULT_PATH",
    "load_custom_frameworks",
    "validate_framework",
]
