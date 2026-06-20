# Runbook: unexpected IAM policy attachment / modification

Covers: `AttachUserPolicy`, `AttachRolePolicy`, `AttachGroupPolicy`,
`PutUserPolicy`, `PutRolePolicy`, `PutGroupPolicy`, `CreatePolicyVersion`,
`SetDefaultPolicyVersion`, `UpdateAssumeRolePolicy`.

## 1. Triage (5 minutes)

- Is the actor a known admin or automation role (Terraform, a CI pipeline)
  doing an expected change? Check your change log / ticket system first —
  most of these fire on legitimate work.
- If unexplained: treat as a live incident, not a false positive, until
  proven otherwise.

## 2. Contain

- If the target principal (user/role/group) now has more access than it
  should: **detach the policy or revert the inline policy immediately.**
  `aws iam detach-user-policy` / `delete-user-policy` (or role/group
  equivalents).
- If `CreatePolicyVersion`/`SetDefaultPolicyVersion` was used: set the
  default version back to the last known-good version
  (`aws iam set-default-policy-version`), then delete the rogue version.
- If the actor's own credentials look compromised (not just misused
  permissions): deactivate their access key(s) and force a console
  password reset.

## 3. Investigate

- Pull every CloudTrail event for that actor's principal ARN in the
  surrounding hour — what did they do immediately before and after this
  action? Look especially for follow-up `AssumeRole`, `CreateAccessKey`,
  or `RunInstances`/`CreateFunction` calls — that's the "now what" half of
  an escalation.
- Check the source IP and user agent against that principal's normal
  pattern (same office IP / same CI runner vs. unfamiliar ASN).
- Confirm whether the *grantor's own* permissions to do this were expected
  — if a low-privileged principal made this call at all, that's a separate
  finding: how did they have that IAM permission in the first place.

## 4. Notify

- Security lead / on-call, immediately if unexplained.
- If this is a regulated environment (FCA, SOC2, etc.), check whether this
  qualifies as a reportable access-control event under your incident
  classification policy.

## 5. Prevent recurrence

- Tighten the IAM permission that allowed this action in the first place
  — cross-reference with `iam-privesc-mapper` to see if this was a known,
  already-flagged escalation path.
