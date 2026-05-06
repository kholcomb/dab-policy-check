#!/usr/bin/env python3
"""P19 - Structural diff of resolved bundle vs deployed bundle.

Compares the resource structure (keys, permissions, run_as, name) between the
locally resolved bundle and the deployed state to detect drift from out-of-band
edits. The bundle is authoritative; any diff fails CI. See P19 in
pre-deploy-checks.md.
"""
import json
import sys
from typing import Any


def normalize(bundle: dict[str, Any]) -> dict[str, Any]:
    """Return {resource_type: {resource_key: {permissions, run_as, name}}}."""
    out: dict[str, Any] = {}
    resources = bundle.get("resources", {})
    for rtype, items in resources.items():
        if not isinstance(items, dict):
            continue
        out[rtype] = {}
        for key, body in items.items():
            if not isinstance(body, dict):
                continue
            entry = {
                "permissions": body.get("permissions"),
                "run_as": body.get("run_as"),
            }
            if "name" in body:
                entry["name"] = body["name"]
            out[rtype][key] = entry
    return out


def diff(resolved: dict[str, Any], deployed: dict[str, Any]) -> list[tuple[str, str]]:
    """Return list of (sigil, label) tuples for added/removed/changed entries."""
    lines: list[tuple[str, str]] = []
    rtypes = set(resolved) | set(deployed)
    for rtype in sorted(rtypes):
        r_keys = set(resolved.get(rtype, {}))
        d_keys = set(deployed.get(rtype, {}))
        for k in sorted(d_keys - r_keys):
            lines.append(("-", f"{rtype}.{k}"))
        for k in sorted(r_keys - d_keys):
            lines.append(("+", f"{rtype}.{k}"))
        for k in sorted(r_keys & d_keys):
            r_entry = resolved[rtype][k]
            d_entry = deployed[rtype][k]
            if r_entry != d_entry:
                changed_fields = sorted(
                    f for f in set(r_entry) | set(d_entry)
                    if r_entry.get(f) != d_entry.get(f)
                )
                lines.append(("~", f"{rtype}.{k} fields={changed_fields}"))
    return lines


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: diff_bundle.py <resolved.json> <deployed.json>", file=sys.stderr)
        return 2
    with open(argv[1]) as f:
        resolved = json.load(f)
    with open(argv[2]) as f:
        deployed = json.load(f)
    lines = diff(normalize(resolved), normalize(deployed))
    for sigil, label in lines:
        print(f"{sigil} {label}")
    return 1 if lines else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
