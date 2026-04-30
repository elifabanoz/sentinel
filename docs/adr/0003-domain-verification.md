# ADR-0003 — DNS TXT Record Domain Verification

**Date:** 2026-04-30  

## Context

Sentinel must only scan domains that the user actually owns. Without verification, any user could scan any domain which would make Sentinel a tool for unauthorized scanning, violating its core ethical constraints.

We needed a verification method that:

1. Proves ownership without requiring server-side file uploads or code changes.
2. Works for any domain regardless of the tech stack running on it.
3. Is simple to implement and understand.

## Decision

We use DNS TXT record verification. When a user adds a domain, Sentinel generates a unique token (e.g. `sentinel-verify-a3f9b2c1`). The user adds this as a DNS TXT record on their domain. Sentinel then performs a DNS TXT lookup if the token is present, the domain is marked as verified.

No HTTP request is ever sent to the domain before the DNS TXT record is confirmed.

## Consequences

**Positive:**

- Proves actual DNS control over the domain, not just knowledge of the URL.
- Works regardless of what is running on the server (no need for file upload or HTML meta tag).
- Industry-standard pattern (used by Google Search Console, Let's Encrypt, etc.) familiar to developers.
- Implementation is simple: Java's `InitialDirContext` for DNS TXT lookup, no external library needed.

**Negative:**

- DNS propagation can take time (up to 48 hours in theory, usually minutes). Users may need to wait.
- Users unfamiliar with DNS management may find it harder than a file upload method.

