#!/usr/bin/env python3
"""P20 - Verify audit log delivery is configured and recent.

Queries system.access.audit on the target workspace via a SQL warehouse and
fails CI if no rows exist or the latest event is older than 24h. The check
itself depends on Unity Catalog system schemas being enabled, which is part
of the operational invariant under verification. See P20 in pre-deploy-checks.md.
"""
import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

from databricks.sdk import WorkspaceClient
from databricks.sdk.service.sql import StatementState

FRESHNESS_HOURS = 24


def parse_args(argv):
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True, help="bundle target name")
    return p.parse_args(argv)


def parse_event_time(raw):
    """Parse a Databricks SQL timestamp string into an aware UTC datetime."""
    s = raw.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def main(argv):
    args = parse_args(argv)
    warehouse_id = os.environ.get("DATABRICKS_WAREHOUSE_ID")
    if not warehouse_id:
        print(
            "[P20/Critical] DATABRICKS_WAREHOUSE_ID env var not set; cannot run audit check",
            file=sys.stderr,
        )
        return 1

    # SDK reads DATABRICKS_HOST + DATABRICKS_CLIENT_ID/SECRET (or profile) from env.
    w = WorkspaceClient()
    resp = w.statement_execution.execute_statement(
        warehouse_id=warehouse_id,
        statement="SELECT max(event_time) AS latest FROM system.access.audit",
        wait_timeout="30s",
    )
    if resp.status and resp.status.state != StatementState.SUCCEEDED:
        print(
            f"[P20/Critical] statement did not succeed: state={resp.status.state}",
            file=sys.stderr,
        )
        return 1

    rows = resp.result.data_array if resp.result else None
    if not rows or not rows[0] or rows[0][0] is None:
        print(
            "[P20/Critical] system.access.audit returned no rows -- "
            "audit log delivery not configured",
            file=sys.stderr,
        )
        return 1

    latest = parse_event_time(rows[0][0])
    age = datetime.now(timezone.utc) - latest
    if age > timedelta(hours=FRESHNESS_HOURS):
        hours = int(age.total_seconds() // 3600)
        print(
            f"[P20/Critical] audit log latest event is {hours} hours old -- "
            "delivery may be broken",
            file=sys.stderr,
        )
        return 1

    print(f"[P20] audit delivery healthy: latest event {latest.isoformat()} (target={args.target})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
