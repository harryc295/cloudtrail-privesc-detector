"""Maps a finding's rule_id to the incident-response runbook that covers it.
Runbooks are grouped by family rather than one-per-rule -- the response
steps for "attached a policy" and "wrote an inline policy" are the same
shape, so they share one document instead of forking five near-duplicates.
"""

RUNBOOK_MAP = {
    "observed-attach-user-policy": "runbooks/policy-attachment.md",
    "observed-attach-role-policy": "runbooks/policy-attachment.md",
    "observed-attach-group-policy": "runbooks/policy-attachment.md",
    "observed-put-user-policy": "runbooks/policy-attachment.md",
    "observed-put-role-policy": "runbooks/policy-attachment.md",
    "observed-put-group-policy": "runbooks/policy-attachment.md",
    "observed-create-policy-version": "runbooks/policy-attachment.md",
    "observed-set-default-policy-version": "runbooks/policy-attachment.md",
    "observed-update-assume-role-policy": "runbooks/policy-attachment.md",
    "observed-create-login-profile": "runbooks/credential-takeover.md",
    "observed-update-login-profile": "runbooks/credential-takeover.md",
    "observed-create-access-key": "runbooks/credential-takeover.md",
    "observed-key-issued-and-used": "runbooks/credential-takeover.md",
    "observed-pass-role-to-lambda": "runbooks/role-passing.md",
    "observed-pass-role-to-ec2": "runbooks/role-passing.md",
    "observed-assume-role-to-admin": "runbooks/assume-role-to-admin.md",
}


def runbook_for(rule_id: str) -> str:
    return RUNBOOK_MAP.get(rule_id, "runbooks/policy-attachment.md")
