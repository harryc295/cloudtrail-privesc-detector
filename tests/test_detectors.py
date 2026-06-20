"""Run with: python -m pytest
(uses -m so the repo root, and therefore detector/, is on sys.path)
"""
from detector.detectors import (
    detect_assume_role_to_admin,
    detect_credential_takeover,
    detect_dangerous_actions,
    detect_key_issued_and_used,
    detect_role_passing,
)


def _event(event_name, principal_arn, **overrides):
    e = {
        "event_time": "2026-06-21T09:00:00+00:00",
        "event_name": event_name,
        "event_source": "iam.amazonaws.com",
        "principal_arn": principal_arn,
        "principal_type": "IAMUser",
        "access_key_id": "AKIAEXAMPLE0000000",
        "source_ip": "203.0.113.10",
        "request_parameters": {},
        "response_elements": {},
        "error_code": None,
    }
    e.update(overrides)
    return e


def test_dangerous_action_flagged_when_successful():
    events = [_event("AttachUserPolicy", "arn:aws:iam::111122223333:user/alice",
                      request_parameters={"userName": "alice", "policyArn": "arn:...:AdministratorAccess"})]
    findings = detect_dangerous_actions(events)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "observed-attach-user-policy"


def test_denied_call_is_not_flagged():
    events = [_event("AttachUserPolicy", "arn:aws:iam::111122223333:user/alice",
                      request_parameters={"userName": "alice"}, error_code="AccessDenied")]
    assert detect_dangerous_actions(events) == []


def test_credential_takeover_requires_different_target():
    self_service = _event("CreateAccessKey", "arn:aws:iam::111122223333:user/bob",
                           request_parameters={})  # no userName -> defaults to self
    takeover = _event("CreateAccessKey", "arn:aws:iam::111122223333:user/dev-lead",
                       request_parameters={"userName": "bob"})
    assert detect_credential_takeover([self_service]) == []
    findings = detect_credential_takeover([takeover])
    assert len(findings) == 1
    assert findings[0]["target"] == "bob"


def test_role_passing_severity_depends_on_admin_roles_context():
    events = [_event("CreateFunction", "arn:aws:iam::111122223333:user/alice", event_source="lambda.amazonaws.com",
                      request_parameters={"role": "arn:aws:iam::111122223333:role/LegacyAutomationRole"})]
    unknown = detect_role_passing(events, admin_roles=set())
    known = detect_role_passing(events, admin_roles={"LegacyAutomationRole"})
    assert unknown[0]["severity"] == "Medium"
    assert known[0]["severity"] == "Critical"


def test_assume_role_to_admin_requires_known_admin_roles():
    events = [_event("AssumeRole", "arn:aws:iam::111122223333:user/charlie", event_source="sts.amazonaws.com",
                      request_parameters={"roleArn": "arn:aws:iam::111122223333:role/LegacyAutomationRole"})]
    assert detect_assume_role_to_admin(events, admin_roles=set()) == []
    findings = detect_assume_role_to_admin(events, admin_roles={"LegacyAutomationRole"})
    assert len(findings) == 1
    assert findings[0]["principal"] == "arn:aws:iam::111122223333:user/charlie"


def test_key_issued_and_used_within_window():
    issued = _event("CreateAccessKey", "arn:aws:iam::111122223333:user/dev-lead",
                     event_time="2026-06-21T09:00:00+00:00",
                     request_parameters={"userName": "bob"},
                     response_elements={"accessKey": {"accessKeyId": "AKIASTOLEN0001"}})
    used_in_window = _event("ListBuckets", "arn:aws:iam::111122223333:user/bob", event_source="s3.amazonaws.com",
                             event_time="2026-06-21T09:06:00+00:00", access_key_id="AKIASTOLEN0001")
    findings = detect_key_issued_and_used([issued, used_in_window], window_minutes=15)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "observed-key-issued-and-used"


def test_key_used_outside_window_is_not_flagged():
    issued = _event("CreateAccessKey", "arn:aws:iam::111122223333:user/dev-lead",
                     event_time="2026-06-21T09:00:00+00:00",
                     request_parameters={"userName": "bob"},
                     response_elements={"accessKey": {"accessKeyId": "AKIASTOLEN0001"}})
    used_later = _event("ListBuckets", "arn:aws:iam::111122223333:user/bob", event_source="s3.amazonaws.com",
                         event_time="2026-06-21T09:30:00+00:00", access_key_id="AKIASTOLEN0001")
    assert detect_key_issued_and_used([issued, used_later], window_minutes=15) == []


def test_self_service_key_rotation_not_flagged_as_takeover():
    issued = _event("CreateAccessKey", "arn:aws:iam::111122223333:user/bob",
                     event_time="2026-06-21T09:00:00+00:00", request_parameters={},
                     response_elements={"accessKey": {"accessKeyId": "AKIAOWN0001"}})
    used = _event("ListBuckets", "arn:aws:iam::111122223333:user/bob", event_source="s3.amazonaws.com",
                   event_time="2026-06-21T09:02:00+00:00", access_key_id="AKIAOWN0001")
    assert detect_key_issued_and_used([issued, used], window_minutes=15) == []
