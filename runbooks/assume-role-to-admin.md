# Runbook: AssumeRole into an admin-equivalent role

Covers: `observed-assume-role-to-admin`. This only fires when the assumed
role is confirmed admin-equivalent (via `--admin-roles`) — AssumeRole on
its own is too common and too often legitimate to alert on blindly, so by
the time this fires, the target role is already known to be high-value.

## 1. Triage

- Is the principal that assumed the role a known break-glass/emergency
  admin identity, used through an expected, audited process (most
  organisations have one)? If so, confirm it was used correctly (ticket,
  approval, time-boxed) and close out.
- If not recognised: treat as a live incident.

## 2. Contain

- You can't directly "kill" an already-issued temporary session, but you
  can cut off its usefulness: attach an explicit `Deny` policy to the
  *source* principal that called AssumeRole, and tighten or remove that
  principal from the role's trust policy.
- If the source principal's own credentials look compromised, deactivate
  them entirely (access key, console password) rather than just blocking
  the one role.

## 3. Investigate

- What did the assumed-role session actually do? Every subsequent
  CloudTrail event with a `userIdentity.arn` matching the assumed-role
  session (not the original principal) shows the blast radius.
- How did the source principal have `sts:AssumeRole` permission *and* a
  trust-policy entry for this role in the first place? If that combination
  was a known finding from `iam-privesc-mapper`'s
  `assume-role-chain-to-admin` rule, this is that exact path being used for
  real.

## 4. Notify

- Security lead / on-call immediately — admin-equivalent access was just
  exercised by a principal that may not have been expected to have it.

## 5. Prevent recurrence

- Lock down the role's trust policy to the smallest possible set of
  principals, and remove `sts:AssumeRole` from anyone who doesn't have a
  documented, current need for it.
