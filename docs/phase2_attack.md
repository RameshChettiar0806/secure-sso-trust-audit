# Phase 2 — Trust Failure Attack (Key Substitution)

## Overview

This phase demonstrates a **critical security failure** that occurs when a system
verifies **only the cryptographic validity** of JWT signatures without validating
the **identity or trustworthiness of the key issuer**.

The attack does **not** break cryptography.

Instead, it exploits the absence of a **trust anchor** that defines which public
keys are legitimate.

---

## Vulnerability Summary

- **Type**: Key Substitution / Issuer Impersonation  
- **Severity**: **CRITICAL**  
- **Root Cause**: Missing issuer trust validation and absence of a trust anchor  

---

## Threat Model

### Attacker Capabilities

The attacker requires **one** of the following:

1. Ability to supply their own public key to the verifier  
2. Ability to influence configuration pointing to a public key source  
3. Any situation where the verifier does not enforce key legitimacy  

No cryptographic weakness or algorithm break is required.

---

## Attack Scenario

### High-Level Description

The system accepts **any RSA public key** for JWT verification.
An attacker generates their own RSA key pair, signs a JWT using RS256,
and provides the matching public key to the verifier.

Because the verifier checks only the **signature**, the forged token is accepted.

---

## Step-by-Step Exploitation

### 1. Attacker Generates RSA Key Pair

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def attacker_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem
```

### 2. Attacker Creates a Malicious JWT (RS256)

```python
import jwt
from datetime import datetime, timedelta, timezone

payload = {
    "sub": "attacker",
    "role": "admin",
    "iat": datetime.now(timezone.utc),
    "exp": datetime.now(timezone.utc) + timedelta(hours=1)
}

malicious_token = jwt.encode(
    payload,
    attacker_private_key,
    algorithm="RS256"
)
```

The token is:

- Cryptographically valid
- Properly timestamped (timezone-aware UTC)
- Signed using RS256

### 3. Verifier Accepts the Forged Token

The verifier performs:

- Signature validation ✔
- Expiry validation ✔

But does not verify:

- Who issued the public key
- Whether the key is trusted
- Whether the issuer is legitimate

As a result, the forged token is accepted.

---

## Why the Attack Works

| Security Check | Phase 2 Behavior | Result |
|----------------|------------------|--------|
| JWT Structure | Valid | PASS |
| RS256 Signature | Valid | PASS |
| Issuer Identity | Not Verified | BYPASSED |
| Trust Anchor | None | BYPASSED |
| Key Legitimacy | Not Verified | BYPASSED |

**A valid signature proves integrity, not identity.**

---

## Impact

- **Authentication Bypass** — attacker can impersonate arbitrary users
- **Authorization Bypass** — attacker can assign themselves privileged roles
- **Privilege Escalation** — no issuer legitimacy enforcement
- **System-Wide Trust Failure** — any key can act as an issuer

---

## Security Insight

This phase highlights a common and dangerous misconception:

> **Cryptographic correctness does not imply trust correctness.**

Without a trusted authority defining which public keys are legitimate,
signature verification alone is insufficient for authentication.

---

## Why This Is a Real-World Issue

This vulnerability has appeared in:

- Naive Single Sign-On (SSO) implementations
- Custom OAuth / JWT deployments
- Internal microservice authentication systems
- Misconfigured Identity and Access Management (IAM) architectures

**This is an architectural failure, not a theoretical flaw.**

---

## How This Leads to Phase 3

To prevent this attack, the system must:

1. Establish a trust anchor
2. Bind public keys to verified identities
3. Reject tokens signed by untrusted issuers

**Phase 3 introduces a Root Certificate Authority (CA)
to define and enforce issuer trust.**

---

## Key Takeaways

- Signature verification alone is insufficient
- Identity requires trust, not just cryptography
- Public keys must be authenticated, not merely accepted
- Trust must be rooted in a verifiable authority

---

## References

- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [JWT Best Current Practices (BCP)](https://datatracker.ietf.org/doc/html/rfc8725)

