#!/usr/bin/env python3
"""CLI: detect actual use of known AWS IAM privilege-escalation techniques
in CloudTrail activity, write an HTML timeline report to ./output.

Usage:
    python main.py --fixture demo/sample_events.json
    python main.py --fixture demo/sample_events.json --admin-roles LegacyAutomationRole
    python main.py --profile my-readonly-profile --lookback-hours 24
"""
import argparse
import sys

import boto3

from detector.collector import collect_live_events, load_admin_roles, load_fixture
from detector.detectors import run_detectors
from detector.report import generate_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--profile", help="AWS CLI profile to scan (read-only cloudtrail:LookupEvents)")
    source.add_argument("--fixture", help="Path to an offline CloudTrail-shaped event JSON fixture")
    parser.add_argument("--lookback-hours", type=int, default=24, help="Live mode only (default: 24)")
    parser.add_argument("--admin-roles", help="Comma-separated role names/ARNs known to be admin-equivalent")
    parser.add_argument("--admin-roles-file", help="JSON file containing a list of admin role names/ARNs")
    parser.add_argument("--window-minutes", type=int, default=15, help="Correlation window (default: 15)")
    parser.add_argument("--out", default="output")
    args = parser.parse_args()

    admin_roles = load_admin_roles(args.admin_roles_file, args.admin_roles)

    if args.fixture:
        events = load_fixture(args.fixture)
        window_note = f"fixture: {args.fixture}"
    else:
        events = collect_live_events(boto3.Session(profile_name=args.profile), args.lookback_hours)
        window_note = f"last {args.lookback_hours}h, profile {args.profile}"

    findings = run_detectors(events, admin_roles=admin_roles, window_minutes=args.window_minutes)
    report_path = generate_report(findings, window_note, out_dir=args.out)

    severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        severities[f["severity"]] = severities.get(f["severity"], 0) + 1
    print(f"{len(events)} events analysed, {len(findings)} findings -> {report_path}")
    print(", ".join(f"{k}: {v}" for k, v in severities.items() if v) or "no findings")

    return 1 if severities["Critical"] else 0


if __name__ == "__main__":
    sys.exit(main())
