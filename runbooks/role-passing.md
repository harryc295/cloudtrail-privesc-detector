# Runbook: role passed to a new Lambda function or EC2 instance

Covers: `observed-pass-role-to-lambda`, `observed-pass-role-to-ec2`.

The risk here is that whatever runs inside the new Lambda function or EC2
instance inherits the passed role's permissions automatically — if that
role is admin-equivalent, anyone who can edit the function code or get a
shell on the instance now effectively has admin.

## 1. Triage

- Is this a known deployment pipeline creating expected infrastructure?
  Most of these are benign CI/CD activity.
- Check the finding's severity: `Critical` means the role is confirmed
  admin-equivalent (cross-referenced against `--admin-roles`); `Medium`
  means privilege is unconfirmed — verify it manually before deciding how
  urgently to respond.

## 2. Contain (if the role is genuinely over-privileged)

- For Lambda: review the function's code immediately
  (`aws lambda get-function`) — has it already been invoked? Check
  `Invocations` in CloudWatch metrics for that function since creation.
  Disable it (`aws lambda put-function-concurrency --reserved-concurrent-executions 0`)
  if it looks unauthorized.
- For EC2: check if the instance is still running and who can reach it
  (security group rules, whether it's in a public subnet). If unexpected,
  stop or isolate the instance (move to a quarantine security group with
  no outbound rules) rather than terminating it immediately — you'll want
  it for forensics.
- Either way: tighten or remove the role's permissions, or revoke the
  ability to pass that specific role going forward
  (`iam:PassRole` scoped with a `Resource` condition).

## 3. Investigate

- Who created the function/instance, and did they have a legitimate
  reason to use *this specific* role rather than a lower-privileged one?
- Check what the function/instance has actually done since creation —
  CloudTrail events where the calling principal is the role's own ARN
  (not the human who created it) show what the *role* did once active.

## 4. Notify

- Whoever owns the role and the affected service — they need to confirm
  whether this was expected.

## 5. Prevent recurrence

- Cross-reference with `iam-privesc-mapper`'s `pass-role-to-new-lambda` /
  `pass-role-to-new-ec2` findings — if this role showed up there already,
  this incident is exactly the predicted risk turning into a real event.
