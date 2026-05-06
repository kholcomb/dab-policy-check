#!/usr/bin/env python3
"""
validate_exceptions.py — lint and notify on policy/exceptions.yaml.

Subcommands:
  lint     PR-time validation: required fields, expiry window, future-dating.
           Optional --codeowners <path> validates the approver against the
           CODEOWNERS rule covering policy/exceptions.yaml.
  notify   Scheduled-pipeline notifier: digest of waivers expiring within
           configurable thresholds, sent to a channel (slack | stdout).

CODEOWNERS validation is opt-in only; without --codeowners it is not
referenced. With --codeowners and a missing/unmatched file, the linter
fails loud rather than silently skipping.

Date sourcing prefers the orchestrator-provided timestamp
(CI_PIPELINE_CREATED_AT or GITHUB_RUN_STARTED_AT) over the runner's local
clock — the orchestrator clock is harder to forge in ephemeral runners.
"""

import argparse
import fnmatch
import json
import os
import sys
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

import yaml


REQUIRED_FIELDS = ("rule_id", "reason", "approver", "approved", "expires")
DEFAULT_MAX_FUTURE_DAYS = 90
DEFAULT_TARGET_PATH = "policy/exceptions.yaml"


def pipeline_today() -> date:
    for var in ("CI_PIPELINE_CREATED_AT", "GITHUB_RUN_STARTED_AT"):
        v = os.environ.get(var)
        if v:
            return datetime.fromisoformat(v.rstrip("Z")).date()
    return datetime.now(timezone.utc).date()


def load_exceptions(path: Path) -> list:
    if not path.exists():
        sys.stderr.write(f"ERROR: exceptions file not found: {path}\n")
        sys.exit(2)
    data = yaml.safe_load(path.read_text()) or []
    if not isinstance(data, list):
        sys.stderr.write(f"ERROR: {path} must be a top-level YAML list.\n")
        sys.exit(2)
    return data


# ---------- CODEOWNERS resolver (opt-in) ----------

def load_codeowners(path: Path) -> list:
    """Returns [(pattern, [owners...]), ...] in file order."""
    if not path.exists():
        sys.stderr.write(f"ERROR: --codeowners path not found: {path}\n")
        sys.exit(2)
    rules = []
    for line in path.read_text().splitlines():
        clean = line.split("#", 1)[0].strip()
        if not clean:
            continue
        parts = clean.split()
        if len(parts) < 2:
            continue
        pattern, *owners = parts
        rules.append((pattern, owners))
    return rules


def codeowners_match(pattern: str, path: str) -> bool:
    p = pattern.lstrip("/")
    if pattern.endswith("/"):
        return path.startswith(p)
    return fnmatch.fnmatch(path, p) or fnmatch.fnmatch(path, p + "/**")


def owners_for(target: str, rules: list) -> set:
    """Last matching pattern wins (GitHub CODEOWNERS semantics)."""
    matched = []
    for pattern, owners in rules:
        if codeowners_match(pattern, target):
            matched = owners
    return set(matched)


# ---------- lint ----------

def lint_entry(
    entry: dict,
    idx: int,
    today: date,
    max_future_days: int,
    codeowner_set: set | None,
) -> list:
    errors = []
    if not isinstance(entry, dict):
        return [f"entry[{idx}]: not a mapping"]

    for field in REQUIRED_FIELDS:
        if not entry.get(field):
            errors.append(f"entry[{idx}]: missing required field {field!r}")
    if errors:
        return errors

    try:
        approved = date.fromisoformat(str(entry["approved"]))
    except ValueError:
        return [f"entry[{idx}]: 'approved' must be ISO YYYY-MM-DD, got {entry['approved']!r}"]

    try:
        expires = date.fromisoformat(str(entry["expires"]))
    except ValueError:
        return [f"entry[{idx}]: 'expires' must be ISO YYYY-MM-DD, got {entry['expires']!r}"]

    if approved > today:
        errors.append(f"entry[{idx}]: 'approved' is in the future ({approved})")
    if expires <= today:
        errors.append(
            f"entry[{idx}]: 'expires' must be in the future "
            f"(got {expires}; today is {today})"
        )
    days_out = (expires - today).days
    if days_out > max_future_days:
        errors.append(
            f"entry[{idx}]: 'expires' is {days_out} days out, exceeds "
            f"max_future_days={max_future_days}. Split into iterative renewals."
        )

    if codeowner_set is not None and entry["approver"] not in codeowner_set:
        errors.append(
            f"entry[{idx}]: approver {entry['approver']!r} is not in CODEOWNERS "
            f"for {DEFAULT_TARGET_PATH}. Eligible: {sorted(codeowner_set)}"
        )

    return errors


def cmd_lint(args: argparse.Namespace) -> int:
    today = pipeline_today()
    exceptions = load_exceptions(args.path)

    codeowner_set = None
    if args.codeowners is not None:
        rules = load_codeowners(args.codeowners)
        if not rules:
            sys.stderr.write(f"ERROR: --codeowners {args.codeowners} contains no rules.\n")
            return 2
        codeowner_set = owners_for(args.target_path, rules)
        if not codeowner_set:
            sys.stderr.write(
                f"ERROR: CODEOWNERS has no rule covering {args.target_path}. "
                f"Add a rule or remove --codeowners.\n"
            )
            return 2

    all_errors = []
    for i, entry in enumerate(exceptions):
        all_errors.extend(lint_entry(entry, i, today, args.max_future_days, codeowner_set))

    if all_errors:
        for e in all_errors:
            sys.stderr.write(f"FAIL: {e}\n")
        return 1

    suffix = " against CODEOWNERS" if codeowner_set is not None else ""
    sys.stdout.write(f"PASS: {len(exceptions)} exception(s) validated{suffix}.\n")
    return 0


# ---------- notify ----------

def bucket_label(days_remaining: int, tiers: list) -> str | None:
    if days_remaining < 0:
        return "expired"
    for t in sorted(tiers):
        if days_remaining <= t:
            return f"<={t}d"
    return None


def render_text_digest(grouped: dict) -> str:
    if not any(grouped.values()):
        return "No exceptions expiring within configured thresholds.\n"
    lines = ["DAB policy waivers — expiring soon", ""]
    order = ["expired"] + sorted(
        (k for k in grouped if k != "expired"),
        key=lambda k: int(k.lstrip("<=").rstrip("d")),
    )
    for tier in order:
        items = grouped.get(tier, [])
        if not items:
            continue
        lines.append(f"== {tier} ({len(items)}) ==")
        for e in items:
            ticket = f"  {e.get('ticket', '')}" if e.get("ticket") else ""
            lines.append(
                f"  {e.get('rule_id', '?'):6s}  {e.get('resource', '*'):60s}  "
                f"expires {e['expires']} ({e['_days_remaining']:+d}d)  "
                f"approver={e.get('approver', '?')}{ticket}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_slack_payload(grouped: dict) -> dict:
    blocks = [{
        "type": "header",
        "text": {"type": "plain_text", "text": "DAB policy waivers — expiring soon"},
    }]
    order = ["expired"] + sorted(
        (k for k in grouped if k != "expired"),
        key=lambda k: int(k.lstrip("<=").rstrip("d")),
    )
    for tier in order:
        items = grouped.get(tier, [])
        if not items:
            continue
        section_lines = [f"*{tier}* ({len(items)})"]
        for e in items:
            ticket = f" <{e['ticket']}|ticket>" if e.get("ticket") else ""
            section_lines.append(
                f"• `{e.get('rule_id', '?')}` `{e.get('resource', '*')}` — "
                f"expires {e['expires']} ({e['_days_remaining']:+d}d) — "
                f"{e.get('approver', '?')}{ticket}"
            )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "\n".join(section_lines)},
        })
    return {"blocks": blocks}


def post_slack(webhook: str, payload: dict) -> None:
    req = urllib.request.Request(
        webhook,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status >= 300:
            sys.stderr.write(f"ERROR: Slack webhook returned HTTP {resp.status}\n")
            sys.exit(2)


def cmd_notify(args: argparse.Namespace) -> int:
    today = pipeline_today()
    exceptions = load_exceptions(args.path)
    warn_days_str = args.warn_days or ""
    tiers = [int(x.strip()) for x in warn_days_str.split(",") if x.strip()]
    if not tiers:
        sys.stderr.write("ERROR: --warn-days produced no tiers.\n")
        return 2

    grouped: dict = {f"<={t}d": [] for t in tiers}
    grouped["expired"] = []

    for entry in exceptions:
        if not isinstance(entry, dict):
            continue
        try:
            expires = date.fromisoformat(str(entry.get("expires", "")))
        except ValueError:
            continue
        days = (expires - today).days
        label = bucket_label(days, tiers)
        if label is None:
            continue
        grouped[label].append({**entry, "_days_remaining": days})

    total = sum(len(v) for v in grouped.values())

    if args.channel == "slack":
        if not args.webhook:
            sys.stderr.write("ERROR: --channel slack requires --webhook URL.\n")
            return 2
        if total == 0:
            sys.stdout.write("No exceptions in any tier; not posting to Slack.\n")
            return 0
        post_slack(args.webhook, render_slack_payload(grouped))
        sys.stdout.write(f"Notified Slack of {total} expiring waiver(s).\n")
        return 0

    sys.stdout.write(render_text_digest(grouped))
    return 0


# ---------- main ----------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    lint = sub.add_parser("lint", help="PR-time validation")
    lint.add_argument("path", type=Path)
    lint.add_argument("--max-future-days", type=int, default=DEFAULT_MAX_FUTURE_DAYS)
    lint.add_argument("--codeowners", type=Path,
                      help="(opt-in) validate approvers against this CODEOWNERS file")
    lint.add_argument("--target-path", default=DEFAULT_TARGET_PATH,
                      help="Path checked against CODEOWNERS rules")
    lint.set_defaults(func=cmd_lint)

    notify = sub.add_parser("notify", help="Scheduled notification")
    notify.add_argument("path", type=Path)
    notify.add_argument("--warn-days", default="7,14,30",
                        help="Comma-separated tier thresholds in days")
    notify.add_argument("--channel", choices=["slack", "stdout"], default="stdout")
    notify.add_argument("--webhook", help="Slack incoming webhook URL")
    notify.set_defaults(func=cmd_notify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
