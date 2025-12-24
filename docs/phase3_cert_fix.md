# Phase 3 — Trust Material Introduced (Attack Still Possible)

## Overview

Phase 3 introduces the **foundational trust material** required to secure the
system: a **Root Certificate Authority (CA)** and an **Identity Provider (IdP)
certificate** issued by that CA.

However, at this stage, the system **does not yet enforce certificate validation**
during JWT verification.

As a result, the **Phase 2 key substitution attack is still possible**.

This phase exists to demonstrate that **trust material alone is insufficient
unless it is actively enforced**.

---

## What Changed in Phase 3

### New Security Components Introduced

- A **Root CA** acting as a trust anchor
- An **IdP RSA key pair**
- An **IdP certificate signed by the Root CA**
- Cryptographically correct issuer–subject relationships

These components establish the **potential for trust**, but not its enforcement.

---

## What Has NOT Changed Yet

Despite the introduction of certificates:

- JWT verification still accepts **raw public keys**
- Certificate chains are **not validated**
- Issuer authenticity is **not enforced**
- The verification flow does **not require a trusted certificate**



---

## Current Verification Flow (Phase 3)

The system still follows this logic:

```
JWT → extract signature
↓
Load public key (no trust check)
↓
Verify RS256 signature
↓
ACCEPT token
```

The presence of certificates **does not alter this flow yet**.

---

## Attack Status in Phase 3

### Attack Type

- **Key Substitution / Issuer Impersonation**

### Attack Outcome

- ✅ **Still succeeds**
- ❌ Not yet prevented

### Why the Attack Still Works

Because:

- The verifier does not validate the IdP certificate
- The Root CA is not consulted during verification
- The public key source is still implicitly trusted

An attacker can still:

1. Supply their own RSA key pair
2. Sign a JWT with RS256
3. Provide the matching public key
4. Have the token accepted

---

## Why This Phase Exists

Phase 3 intentionally separates two concepts:

| Concept | Status |
|---------|--------|
| Trust Material Exists | ✅ |
| Trust Is Enforced | ❌ |

This separation demonstrates an important security principle:

> **Security mechanisms are ineffective unless they are enforced.**

Merely generating certificates does not secure the system.

---

## Security Insight

Phase 3 highlights a subtle but common pitfall:

> "We have certificates, therefore we are secure."

This is false.

Certificates only become meaningful when:

- A trust anchor is defined **and**
- Certificate validation is mandatory **and**
- All untrusted issuers are rejected

Until then, the attack surface remains unchanged.

---

## Verification Evidence (Phase 3 Checks)

The following have been cryptographically verified:

- Root CA has `BasicConstraints(ca=True)`
- IdP certificate has `BasicConstraints(ca=False)`
- IdP certificate is signed by Root CA
- IdP private key matches IdP certificate public key

Despite this, the attack persists.

---

## Phase Boundary Clarification

- **Phase 2**: Demonstrated the attack
- **Phase 3**: Introduced trust material
- **Phase 4**: Enforces trust and prevents the attack

Phase 3 is a **necessary but insufficient** step toward security.

---

## Transition to Phase 4

In **Phase 4**, the verification flow will change fundamentally:

```
JWT
↓
Load IdP certificate
↓
Validate certificate against Root CA
↓
Extract trusted public key
↓
Verify JWT signature
↓
ACCEPT token
```

Any failure in certificate validation will result in **token rejection**.

---

## Key Takeaways

- Certificates alone do not provide security
- Trust must be actively enforced
- Phase 3 prepares the system for enforcement
- Phase 2 attack persists until Phase 4

---

## Phase 3 Status

At the end of Phase 3:

- Trust material exists
- Trust is not yet enforced
- The system remains vulnerable by design

This concludes **Phase 3 — Trust Material Introduction** and sets the stage for  
**Phase 4 — Certificate Chain Validation & Attack Prevention**.

- RFC 5280: X.509 Certificate Validation
- NIST Guidelines on Cryptographic Algorithms
- OWASP: Cryptographic Failures
- CWE-295: Improper Certificate Validation
