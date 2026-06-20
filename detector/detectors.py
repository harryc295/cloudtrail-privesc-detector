"""Detects actual use of known AWS IAM privilege-escalation techniques in
CloudTrail activity -- the companion to iam-privesc-mapper, which finds
paths that *could* be used. This finds techniques actually *being* used.

LIMITATION (documented, not hidden): CloudTrail confirms an action
succeeded, which means IAM already authorized it -- this tool can't tell
"an admin doing admin things" apart from "someone who shouldn't have had
that permission using it" on its own. That's exactly the ambiguity a human
(or a cross-reference against iam-privesc-mapper's admin-role findings via
--admin-roles) resolves. Every finding here is "this powerful action
happened, go look," not a verdict.
"""
from datetime import datetime, timedelta


def _parse_time(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _username_from_arn(arn: str) -> str:
    return arn.rsplit("/", 1)[-1] if arn else ""


def _finding(rule_id, title, severity, principal_arn, principal_type, target, evidence, event_time):
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "principal": principal_arn,
        "principal_type": principal_type,
        "target": target,
        "evidence": evidence,
        "event_time": event_time,
    }


# event_name, rule_id, severity, request-param key holding the target name, description
_DANGEROUS_ACTIONS = [
    ("AttachUserPolicy", "observed-attach-user-policy", "Critical", "userName",
     "attached a managed policy directly to an IAM user"),
    ("AttachRolePolicy", "observed-attach-role-policy", "Critical", "roleName",
     "attached a managed policy to an IAM role"),
    ("AttachGroupPolicy", "observed-attach-group-policy", "Critical", "groupName",
     "attached a managed policy to an IAM group"),
    ("PutUserPolicy", "observed-put-user-policy", "Critical", "userName",
     "wrote a new inline policy on an IAM user"),
    ("PutRolePolicy", "observed-put-role-policy", "High", "roleName",
     "wrote a new inline policy on an IAM role"),
    ("PutGroupPolicy", "observed-put-group-policy", "High", "groupName",
     "wrote a new inline policy on an IAM group"),
    ("CreatePolicyVersion", "observed-create-policy-version", "Critical", "policyArn",
     "created a new version of a managed policy"),
    ("SetDefaultPolicyVersion", "observed-set-default-policy-version", "Critical", "policyArn",
     "changed which version of a managed policy is active"),
    ("UpdateAssumeRolePolicy", "observed-update-assume-role-policy", "High", "roleName",
     "rewrote an IAM role's trust policy"),
]

# event_name, rule_id, severity, request-param key holding the target username
_CREDENTIAL_TAKEOVER_ACTIONS = [
    ("CreateLoginProfile", "observed-create-login-profile", "High", "userName"),
    ("UpdateLoginProfile", "observed-update-login-profile", "High", "userName"),
    ("CreateAccessKey", "observed-create-access-key", "Critical", "userName"),
]


def detect_dangerous_actions(events: list[dict]) -> list[dict]:
    by_action = {a[0]: a for a in _DANGEROUS_ACTIONS}
    findings = []
    for e in events:
        action = by_action.get(e["event_name"])
        if not action or e["error_code"]:
            continue
        _, rule_id, severity, target_key, description = action
        target = e["request_parameters"].get(target_key, "unknown")
        findings.append(_finding(
            rule_id, e["event_name"], severity, e["principal_arn"], e["principal_type"], target,
            f"{e['principal_arn']} {description} (target: {target}).", e["event_time"],
        ))
    return findings


def detect_credential_takeover(events: list[dict]) -> list[dict]:
    by_action = {a[0]: a for a in _CREDENTIAL_TAKEOVER_ACTIONS}
    findings = []
    for e in events:
        action = by_action.get(e["event_name"])
        if not action or e["error_code"]:
            continue
        _, rule_id, severity, target_key = action
        target = e["request_parameters"].get(target_key) or _username_from_arn(e["principal_arn"])
        actor_name = _username_from_arn(e["principal_arn"])
        if target == actor_name:
            continue  # self-service (e.g. rotating your own access key) -- not the interesting case
        findings.append(_finding(
            rule_id, e["event_name"], severity, e["principal_arn"], e["principal_type"], target,
            f"{e['principal_arn']} called {e['event_name']} targeting a *different* user "
            f"({target}) -- credential takeover, not self-service.", e["event_time"],
        ))
    return findings


def detect_role_passing(events: list[dict], admin_roles: set[str] | None = None) -> list[dict]:
    admin_roles = admin_roles or set()
    findings = []
    for e in events:
        if e["error_code"] or e["event_name"] not in ("CreateFunction", "RunInstances"):
            continue
        rp = e["request_parameters"]
        if e["event_name"] == "CreateFunction":
            role_arn = rp.get("role")
            action_desc = "created a Lambda function and passed it"
            rule_id = "observed-pass-role-to-lambda"
        else:
            profile = rp.get("iamInstanceProfile") or {}
            role_arn = profile.get("arn") or profile.get("name")
            action_desc = "launched an EC2 instance with attached instance profile"
            rule_id = "observed-pass-role-to-ec2"
        if not role_arn:
            continue
        role_name = _username_from_arn(role_arn)
        known_admin = role_name in admin_roles or role_arn in admin_roles
        severity = "Critical" if known_admin else "Medium"
        caveat = "" if known_admin else " (role privilege unknown -- pass --admin-roles to confirm)"
        findings.append(_finding(
            rule_id, e["event_name"], severity, e["principal_arn"], e["principal_type"], role_name,
            f"{e['principal_arn']} {action_desc} role {role_name}{caveat}.", e["event_time"],
        ))
    return findings


def detect_assume_role_to_admin(events: list[dict], admin_roles: set[str] | None = None) -> list[dict]:
    # AssumeRole is extremely common and mostly benign -- only alert when we
    # positively know the target role is admin-equivalent, otherwise this is
    # 95% noise.
    admin_roles = admin_roles or set()
    if not admin_roles:
        return []
    findings = []
    for e in events:
        if e["error_code"] or e["event_name"] != "AssumeRole":
            continue
        role_arn = e["request_parameters"].get("roleArn", "")
        role_name = _username_from_arn(role_arn)
        if role_name not in admin_roles and role_arn not in admin_roles:
            continue
        findings.append(_finding(
            "observed-assume-role-to-admin", e["event_name"], "Critical",
            e["principal_arn"], e["principal_type"], role_name,
            f"{e['principal_arn']} assumed admin-equivalent role {role_name}.", e["event_time"],
        ))
    return findings


def detect_key_issued_and_used(events: list[dict], window_minutes: int = 15) -> list[dict]:
    window = timedelta(minutes=window_minutes)
    issued = []
    for e in events:
        if e["error_code"] or e["event_name"] != "CreateAccessKey":
            continue
        target = e["request_parameters"].get("userName") or _username_from_arn(e["principal_arn"])
        creator = e["principal_arn"]
        if _username_from_arn(creator) == target:
            continue  # self-service key rotation
        new_key = (e.get("response_elements") or {}).get("accessKey", {}).get("accessKeyId")
        if new_key:
            issued.append((_parse_time(e["event_time"]), creator, target, new_key, e["event_time"]))

    findings = []
    for issued_at, creator, target, key_id, issued_at_str in issued:
        for e in events:
            if e.get("access_key_id") != key_id:
                continue
            used_at = _parse_time(e["event_time"])
            if issued_at < used_at <= issued_at + window:
                findings.append(_finding(
                    "observed-key-issued-and-used", "CreateAccessKey -> immediate use", "Critical",
                    creator, "Unknown", target,
                    f"{creator} created an access key for {target}; it was used "
                    f"{used_at - issued_at} later from {e.get('source_ip', 'unknown IP')} "
                    f"to call {e['event_name']} -- classic credential-issuance-and-immediate-use pattern.",
                    issued_at_str,
                ))
                break  # one finding per issued key is enough
    return findings


def run_detectors(events: list[dict], admin_roles: set[str] | None = None,
                   window_minutes: int = 15) -> list[dict]:
    findings = []
    findings += detect_dangerous_actions(events)
    findings += detect_credential_takeover(events)
    findings += detect_role_passing(events, admin_roles)
    findings += detect_assume_role_to_admin(events, admin_roles)
    findings += detect_key_issued_and_used(events, window_minutes)
    return findings
