# Runbook: credential takeover (login profile / access key for another user)

Covers: `CreateLoginProfile`, `UpdateLoginProfile`, `CreateAccessKey`
(targeting a *different* user than the caller), and the correlated
`observed-key-issued-and-used` finding (a new key created for someone, then
used within minutes).

This family is the most urgent of the three runbooks — a successful hit
here means someone other than the account owner can now authenticate as
them.

## 1. Triage (immediately, don't wait)

- Was this a help-desk/offboarding workflow doing an expected password
  reset? Check for a matching ticket.
- If `observed-key-issued-and-used` fired: this is the highest-confidence
  signal in the whole tool. Treat as an active incident by default.

## 2. Contain (do this first, investigate after)

- **Deactivate the new access key immediately:**
  `aws iam update-access-key --status Inactive`.
- **Delete the console login profile** if one was just created/reset
  without the user's knowledge: `aws iam delete-login-profile`.
- If the target user's existing credentials might also be compromised
  (not just the new ones), rotate everything they hold — all access keys,
  console password, active MFA devices.
- Revoke any active sessions for the target principal if they were
  assuming a role (`aws iam` doesn't have a direct "kill session" call for
  long-term creds, but you can attach an explicit Deny policy as an
  immediate circuit-breaker while you work).

## 3. Investigate

- What did the new key / new login actually get used for, in the window
  between issuance and detection? Pull every event tied to that
  `accessKeyId`.
- Was the creator's own account compromised, or do they have a legitimate
  (if undocumented) reason to manage other users' credentials? Both are
  real possibilities — don't assume malice, but don't dismiss it either.
- Check source IP/geolocation on both the creation event and the first-use
  event — a mismatch between them is a strong corroborating signal.

## 4. Notify

- Security lead / on-call immediately — this is the runbook most likely to
  need a formal incident declared.
- The affected user, once contained — they need to know their identity
  was touched.
- Compliance/legal if you're in a regulated environment and this looks
  like unauthorized account access, not an internal process error.

## 5. Prevent recurrence

- Review who holds `iam:CreateAccessKey` / `iam:CreateLoginProfile` /
  `iam:UpdateLoginProfile` for principals other than themselves — this
  should be a very small, well-audited list.
