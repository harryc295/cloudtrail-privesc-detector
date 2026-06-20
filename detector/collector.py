"""Pulls and normalizes CloudTrail events. Read-only: only cloudtrail:LookupEvents.

`lookup_events` reads the account's default 90-day event history -- no S3
export bucket, no Athena table, no extra infra to deploy. Good enough for a
detector that needs "what just happened," not long-term log retention.

Normalized event shape (same for live AWS and demo/*.json fixtures):

    {
      "event_time": "2026-06-21T10:15:00+00:00",
      "event_name": "AttachUserPolicy",
      "event_source": "iam.amazonaws.com",
      "principal_arn": "arn:aws:iam::111122223333:user/alice",
      "principal_type": "IAMUser",
      "access_key_id": "AKIA...",        # set when the caller used long-term creds
      "source_ip": "203.0.113.5",
      "request_parameters": {...},
      "response_elements": {...},
      "error_code": null,                # set when the call was denied -- ignored by detectors
    }
"""
import json

import boto3


def normalize_event(raw: dict) -> dict:
    user_identity = raw.get("userIdentity", {})
    return {
        "event_time": raw.get("eventTime"),
        "event_name": raw.get("eventName"),
        "event_source": raw.get("eventSource"),
        "principal_arn": user_identity.get("arn", "unknown"),
        "principal_type": user_identity.get("type", "Unknown"),
        "access_key_id": user_identity.get("accessKeyId"),
        "source_ip": raw.get("sourceIPAddress"),
        "request_parameters": raw.get("requestParameters") or {},
        "response_elements": raw.get("responseElements") or {},
        "error_code": raw.get("errorCode"),
    }


def load_fixture(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        events = json.load(fh)
    return sorted(events, key=lambda e: e["event_time"])


def collect_live_events(session: boto3.Session, lookback_hours: int = 24) -> list[dict]:
    import datetime

    client = session.client("cloudtrail")
    start_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=lookback_hours)
    events = []
    for page in client.get_paginator("lookup_events").paginate(StartTime=start_time):
        for item in page["Events"]:
            raw = json.loads(item["CloudTrailEvent"])
            events.append(normalize_event(raw))
    return sorted(events, key=lambda e: e["event_time"])


def load_admin_roles(path: str | None, inline: str | None) -> set[str]:
    """Optional context: role names/ARNs known to be admin-equivalent.
    Generate this from iam-privesc-mapper's already-admin-equivalent
    findings, or list roles yourself -- the two tools are independent,
    this is just a plain text/JSON hand-off between them."""
    roles: set[str] = set()
    if inline:
        roles |= {r.strip() for r in inline.split(",") if r.strip()}
    if path:
        with open(path, encoding="utf-8") as fh:
            roles |= set(json.load(fh))
    return roles
