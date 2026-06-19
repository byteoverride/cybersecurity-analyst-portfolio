# From Bug Bounty Finding to Detection Rule

**Author:** Psalms ([@byteoverride](https://hackerone.com/byteoverride))  
**Date:** May 2026  
**Tags:** purple-team, sigma, account-takeover, detection-engineering

* * *

## TL;DR

I found an account takeover vulnerability via session persistence  old session cookies remained valid after password reset. This post walks through how I translated that offensive finding into a defensive Sigma rule mapped to MITRE T1550.004 (Web Session Cookie) and T1078 (Valid Accounts). The rule is in this repo at [`purple-team/session_persistence_post_reset.yml`](/tmp/.mount_JoplindbCERk/resources/app.asar/purple-team/session_persistence_post_reset.yml "purple-team/session_persistence_post_reset.yml").

The interesting bit isn't the bug. It's the inversion: most detection logic looks for *new* sessions appearing where they shouldn't. This rule looks for *old* sessions that should have disappeared but didn't. Defenders rarely instrument for that gap.

* * *

## The attacker's view

While testing a target during bug bounty research, I noticed a behaviour pattern in how the application handled password resets. When a user changed their password, the application:

1.  Updated the password hash in the database.
2.  Issued a UI confirmation that the password had been changed.
3.  **Did not invalidate active sessions associated with that account.**

The session cookie I had captured before the password change continued to work afterward. That's the entire bug  but the impact is severe. The standard account takeover flow becomes:

```
Step 1: Attacker compromises credentials (phishing, leaked password, etc.)
Step 2: Attacker logs in, captures session cookie
Step 3: Legitimate user notices something is wrong, changes password
Step 4: Legitimate user assumes they have evicted the attacker
Step 5: Attacker's session cookie still works → persistent access
```

From the user's perspective, they did everything right. From the attacker's perspective, the password reset is a no-op against an already-established session.

This maps cleanly to MITRE [T1550.004  Use Alternate Authentication Material: Web Session Cookie](https://attack.mitre.org/techniques/T1550/004/). The attacker isn't authenticating with credentials anymore  they're authenticating with a session token that should have been revoked.

* * *

## The defender's pivot

Once you've written the report and moved on, you can ask the more interesting question: **how would I have caught this from the defender's side?**

This is where most detection engineering goes wrong. The natural instinct is to look for the attacker's *new* activity  a login from a new IP, an unusual user agent, a geographic anomaly. That logic works for stolen credentials. It does **not** work for session reuse, because:

- The session is the same session the legitimate user established.
- The IP may not change if the attacker is already on a similar network.
- The user agent matches the captured browser fingerprint.
- The token is cryptographically valid.

Everything that the standard "anomalous login" rule looks for, the attacker has already passed.

So you flip the question. Instead of asking *"is this login unusual?"*, you ask *"is there a session in use that should not exist anymore?"*

* * *

## Building the rule

The detection logic for `session_persistence_post_reset.yml`:

1.  **Capture the password change event.** Note its timestamp, the source IP that triggered it, the user agent, and the geographic context.
2.  **Tag all subsequent authenticated requests** with the issued-at (`iat`) timestamp of the token they used.
3.  **Alert** when any authenticated request uses a token whose `iat` predates the password change — *especially* when the source IP, user agent, or geography of that request differs from the source that performed the password change.

```yaml
detection:
    password_change_event:
        event_type: 'password_change'
        result: 'success'
    authenticated_request:
        event_type: 'authenticated_request'
        token_issued_at|lt|field: 'password_changed_at'
    suspicious_indicators:
        token_issued_at|lt|field: 'password_changed_at'
        OR:
            - src_ip|notequal|field: 'password_change_src_ip'
            - user_agent|notequal|field: 'password_change_user_agent'
            - geo_country|notequal|field: 'password_change_geo_country'
    condition: authenticated_request and suspicious_indicators
```

The rule is intentionally **noisy on a vulnerable system and quiet on a secure one**. If the application properly invalidates sessions on password change, this rule fires zero alerts because the precondition (`token_issued_at < password_changed_at`) is never satisfied. If the application is vulnerable, every single authenticated request from the attacker becomes an alert.

That's the property you want from a behavioral rule  it's a litmus test for the underlying control, not just a tripwire for known bad activity.

* * *

## Implementation requirements

For this rule to work in a real environment, the application must emit two log streams with structured fields:

**`password_change` events:**

```json
{
  "event_type": "password_change",
  "user_id": "u_12345",
  "timestamp": "2026-05-15T14:23:11Z",
  "src_ip": "203.0.113.42",
  "user_agent": "Mozilla/5.0 ...",
  "geo_country": "UG",
  "result": "success"
}
```

**`authenticated_request` events:**

```json
{
  "event_type": "authenticated_request",
  "user_id": "u_12345",
  "timestamp": "2026-05-15T14:31:55Z",
  "token_issued_at": "2026-05-15T13:50:02Z",
  "src_ip": "198.51.100.7",
  "user_agent": "Mozilla/5.0 ...",
  "geo_country": "US"
}
```

If your application doesn't log `token_issued_at`, that's the first gap to close. JWT tokens carry `iat` in the payload. Opaque session IDs can have their creation timestamp logged alongside the ID in the session store. Either works.

* * *

## Evasion analysis

Could an attacker evade this rule? I asked myself the question I ask of every Sigma rule I write  and the honest answer is **yes, partially**.

**Evasion 1: Token refresh.** If the application supports token refresh, an attacker can swap their old token for a new one *before* the legitimate user resets the password. The new token has a recent `iat` and won't satisfy the rule's condition.

- **Mitigation:** The refresh should also be invalidated on password change. The detection requirement is the same  invalidate session material, not just the password.

**Evasion 2: Coordinated takeover.** If the attacker performs the password change themselves (e.g., they have email access too), then `password_change_src_ip` is the *attacker's* IP and subsequent requests from the same IP look normal.

- **Mitigation:** This is no longer a session-persistence problem  it's full account compromise. Detect upstream via the password reset email flow itself.

**Evasion 3: IP/UA spoofing.** If the attacker can mirror the legitimate user's IP and user-agent, the `suspicious_indicators` OR clause won't fire. The rule still alerts on the base `token_issued_at < password_changed_at` condition, but at lower severity.

- **Mitigation:** Treat the base condition as a high-confidence indicator even without the other signals. Sessions surviving a password change is *always* anomalous.

The rule's primary value is not as a perfect detection  it is **a litmus test for whether the session invalidation control works**. If this rule starts firing in production, the security team has two findings, not one: an active attack AND a broken control.

* * *

## Why this matters

This is the kind of work that closes the gap between offensive and defensive security. Every bug bounty finding contains within it a detection opportunity  the technique that worked for the attacker becomes a signature for the defender.

Most detection engineers don't write rules from their own offensive research because they don't do offensive research. Most bug bounty hunters don't write detection rules because they don't think about the defender's view. The intersection is small, and it's where genuinely novel detection ideas come from.

The Sigma format makes this kind of cross-domain work practical  write the rule once, convert it to Splunk, Elastic, Sentinel, or whatever the target SIEM is. The thinking is portable; the implementation is automated.

* * *

## References

- [MITRE T1550.004 — Web Session Cookie](https://attack.mitre.org/techniques/T1550/004/)
- [MITRE T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [Sigma Specification — Correlation Rules](https://github.com/SigmaHQ/sigma-specification)
- The rule itself: [`purple-team/session_persistence_post_reset.yml`](/tmp/.mount_JoplindbCERk/resources/app.asar/purple-team/session_persistence_post_reset.yml "purple-team/session_persistence_post_reset.yml")

* * *

*Found a flaw in the rule? Open an issue or hit me up on [HackerOne](https://hackerone.com/byteoverride). Detection rules are a conversation, not a finished product.*
