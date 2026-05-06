#!/usr/bin/env python3
"""
conftest_report.py — Rich pre-deploy policy reporting for Databricks Asset Bundles.

Runs `conftest test` against a resolved bundle JSON, joins each finding with a
YAML rule catalog (rule_id -> {title, severity, why, fix, references}), and
emits Markdown and/or JUnit reports. Exits non-zero if any finding meets or
exceeds the configured severity threshold.

Usage:
  python conftest_report.py \\
      --policy policy/ \\
      --catalog policy/dab.catalog.yaml \\
      --bundle bundle.resolved.json \\
      --markdown report.md \\
      --junit conftest-report.xml \\
      --fail-on high

Fails fast if conftest is missing, the catalog is missing an entry for any
finding, or any deny message does not match the expected `[<id>/<sev>] <body>
(resource: <path>)` shape — these are policy-pack bugs, not user errors.
"""

import argparse
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
SEVERITY_LABEL = {
    "Critical": "[CRITICAL]",
    "High":     "[HIGH]",
    "Medium":   "[MEDIUM]",
    "Low":      "[LOW]",
}

MSG_RE = re.compile(
    r"^\[(?P<id>P\d+)/(?P<sev>\w+)\]\s*"
    r"(?P<body>.*?)\s*"
    r"\(resource:\s*(?P<resource>[^)]+)\)\s*$"
)


def run_conftest(policy_dir: Path, bundle: Path) -> list:
    """Run conftest, return parsed JSON list. Conftest exits non-zero on findings;
    that is normal. An empty stdout indicates a real error (compile failure, etc.)."""
    completed = subprocess.run(
        ["conftest", "test",
         "--policy", str(policy_dir),
         "--all-namespaces",
         "--output", "json",
         str(bundle)],
        capture_output=True,
        text=True,
        check=False,
    )
    if not completed.stdout.strip():
        sys.stderr.write(completed.stderr)
        sys.stderr.write(f"\nERROR: conftest produced no JSON output (exit {completed.returncode}).\n")
        sys.exit(2)
    return json.loads(completed.stdout)


def parse_finding(failure: dict) -> dict:
    msg = failure.get("msg", "")
    m = MSG_RE.match(msg)
    if not m:
        sys.stderr.write(f"ERROR: deny message does not match required format:\n  {msg!r}\n")
        sys.stderr.write("Expected: [<id>/<sev>] <body> (resource: <path>)\n")
        sys.exit(2)
    return {
        "rule_id": m.group("id"),
        "severity": m.group("sev").capitalize(),
        "body": m.group("body"),
        "resource": m.group("resource"),
    }


def collect_findings(conftest_output: list) -> list:
    findings = []
    for result in conftest_output:
        for failure in result.get("failures") or []:
            findings.append(parse_finding(failure))
    return findings


def join_with_catalog(findings: list, catalog: dict) -> list:
    enriched = []
    for f in findings:
        cat = catalog.get(f["rule_id"])
        if cat is None:
            sys.stderr.write(
                f"ERROR: finding for rule {f['rule_id']} has no catalog entry. "
                f"Add it to dab.catalog.yaml.\n"
            )
            sys.exit(2)
        if cat.get("severity") and cat["severity"] != f["severity"]:
            sys.stderr.write(
                f"WARNING: severity drift for {f['rule_id']}: rule emits {f['severity']}, "
                f"catalog says {cat['severity']}. Reporting rule severity.\n"
            )
        enriched.append({
            "rule_id":    f["rule_id"],
            "severity":   f["severity"],
            "body":       f["body"],
            "resource":   f["resource"],
            "title":      cat.get("title", f["rule_id"]),
            "why":        cat.get("why", "").strip(),
            "fix":        cat.get("fix", "").strip(),
            "references": cat.get("references", []) or [],
        })
    return enriched


def severity_counts(findings: list) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


def render_markdown(findings: list, counts: dict) -> str:
    total = sum(counts.values())
    if total == 0:
        return "# DAB pre-deploy policy: PASS\n\nAll rules passed.\n"

    summary = ", ".join(
        f"{counts[s]} {s}" for s in ("Critical", "High", "Medium", "Low") if counts[s]
    )
    lines = [f"# DAB pre-deploy policy: {total} finding(s)", "", f"_{summary}_", ""]

    grouped = {s: [] for s in SEVERITY_ORDER}
    for f in findings:
        grouped[f["severity"]].append(f)

    for sev in ("Critical", "High", "Medium", "Low"):
        if not grouped[sev]:
            continue
        lines.append(f"## {SEVERITY_LABEL[sev]} ({len(grouped[sev])})")
        lines.append("")
        for f in grouped[sev]:
            lines.append(f"### {f['rule_id']} — {f['title']}")
            lines.append("")
            lines.append(f"**Resource:** `{f['resource']}`")
            lines.append("")
            lines.append(f"**Detection:** {f['body']}")
            lines.append("")
            if f["why"]:
                lines.append("**Why:**")
                lines.append("")
                lines.append(f["why"])
                lines.append("")
            if f["fix"]:
                lines.append("**Fix:**")
                lines.append("")
                lines.append(f["fix"])
                lines.append("")
            if f["references"]:
                lines.append("**References:**")
                lines.append("")
                for ref in f["references"]:
                    lines.append(f"- {ref}")
                lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_junit(findings: list) -> str:
    suite = ET.Element("testsuite", {
        "name": "DAB pre-deploy policy",
        "tests": str(len(findings)),
        "failures": str(len(findings)),
    })
    for f in findings:
        case = ET.SubElement(suite, "testcase", {
            "name": f"{f['rule_id']}: {f['title']}",
            "classname": f"dab.{f['severity']}",
        })
        body = (
            f"[{f['severity']}] {f['title']}\n"
            f"Resource: {f['resource']}\n"
            f"Detection: {f['body']}\n\n"
            f"Why:\n{f['why']}\n\n"
            f"Fix:\n{f['fix']}\n"
        )
        failure = ET.SubElement(case, "failure", {
            "type": f["severity"],
            "message": f["title"],
        })
        failure.text = body
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(suite, encoding="unicode")


def render_json(findings: list, counts: dict) -> str:
    return json.dumps({
        "summary": counts,
        "total": sum(counts.values()),
        "findings": findings,
    }, indent=2)


def write_output(path: Path | None, content: str) -> None:
    if path is None:
        return
    path.write_text(content)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--policy", type=Path, required=True, help="Rego policy directory")
    parser.add_argument("--catalog", type=Path, required=True, help="dab.catalog.yaml")
    parser.add_argument("--bundle", type=Path, required=True, help="Resolved bundle JSON")
    parser.add_argument("--markdown", type=Path, help="Write Markdown report to this path")
    parser.add_argument("--junit", type=Path, help="Write JUnit XML report to this path")
    parser.add_argument("--json", dest="json_out", type=Path, help="Write JSON report to this path")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
        help="Minimum severity that causes non-zero exit (default: high)",
    )
    args = parser.parse_args()

    catalog = yaml.safe_load(args.catalog.read_text()) or {}
    conftest_output = run_conftest(args.policy, args.bundle)
    findings = collect_findings(conftest_output)
    findings = join_with_catalog(findings, catalog)
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["rule_id"], f["resource"]))
    counts = severity_counts(findings)

    write_output(args.markdown, render_markdown(findings, counts))
    write_output(args.junit, render_junit(findings))
    write_output(args.json_out, render_json(findings, counts))

    if not (args.markdown or args.junit or args.json_out):
        sys.stdout.write(render_markdown(findings, counts))

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on.capitalize()]
    breach = [f for f in findings if SEVERITY_ORDER[f["severity"]] >= threshold]
    if breach:
        sys.stderr.write(
            f"\nFAIL: {len(breach)} finding(s) at or above severity '{args.fail_on}'.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
