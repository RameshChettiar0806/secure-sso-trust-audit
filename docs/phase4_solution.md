# Phase 4 — Solution: Certificate Chain Validation & Attack Prevention

## Overview

Phase 4 completes the security architecture of the system by **enforcing
certificate-based trust** for JWT verification.

At this stage, JWTs are no longer accepted based solely on cryptographic
signature validity. Instead, every token must be issued by a **trusted Identity
Provider (IdP)** whose certificate is **cryptographically verified against a
Root Certificate Authority (CA)**.

This phase **permanently eliminates the key substitution attack** demonstrated
in Phase 2.

---

## Security Goal

> Ensure that **only a trusted issuer can produce an acceptable JWT**, even if
> an attacker uses valid cryptography and the same signing algorithm (RS256).

---

## Final Trust Model

Root Certificate Authority (Trust Anchor)
↓ verifies
Identity Provider Certificate
↓ provides trusted public key
JWT Signature (RS256)

JWT verification is performed **only after** this trust chain is validated.

---

## What Changed in Phase 4

### Enforced Security Controls

- A **Root CA** is defined as the sole trust anchor
- The **IdP certificate** is validated against the Root CA
- The IdP public key is extracted **only after successful certificate validation**
- JWT signature verification uses **only the trusted IdP public key**

### Deprecated / Removed Assumptions

- Trusting raw RSA public keys
- Accepting tokens based solely on signature validity
- Implicit trust in key sources or configuration

---

## Secure Verification Flow

```text
Incoming JWT
	↓
Load IdP certificate
	↓
Validate IdP certificate against Root CA
	↓
Extract trusted IdP public key
	↓
Verify JWT signature (RS256)
	↓
ACCEPT token
```

If any step fails, the token is rejected immediately.

---

## Attack Mitigation Result

**Attack Previously Demonstrated**: Key Substitution / Issuer Impersonation

- Attacker signs a JWT using their own RSA key
- Cryptographic signature is valid

**Phase 4 Outcome**: The attack is fully blocked.

Example response from the secure verification endpoint:

```json
{
  "status": "attack blocked",
  "reason": "Signature verification failed"
}
```

The failure occurs because the forged JWT was not signed by the trusted IdP
private key, even though the cryptography itself is valid.

---

## Why the Solution Works

| Security Property | Status |
|-------------------|--------|
| Root CA trust anchor | ✅ Enforced |
| IdP certificate validation | ✅ Enforced |
| Issuer identity verification | ✅ Enforced |
| JWT integrity verification | ✅ Enforced |
| Acceptance of attacker keys | ❌ Rejected |

The system no longer answers “Is this signature valid?”
It answers “Is this signature from a trusted issuer?”

---

## Comparison Across Phases

| Phase | Security State |
|-------|----------------|
| Phase 1 | Implicit trust in public keys |
| Phase 2 | Attack succeeds (key substitution) |
| Phase 3 | Trust material exists but unused |
| Phase 4 | Trust enforced, attack blocked |

---

## Key Security Insights

- Cryptographic validity does not imply issuer legitimacy
- Public keys must be authenticated, not assumed
- Certificates are meaningless unless validated
- Trust must be enforced before JWT verification
- A Root CA is essential for secure SSO systems
