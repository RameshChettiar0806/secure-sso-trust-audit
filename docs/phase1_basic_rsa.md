# Phase 1 — Baseline JWT Verification (Implicit Trust Assumption)

## Overview

Phase 1 implements a **baseline JWT authentication mechanism** using the RS256
algorithm, where JWT signatures are verified using a directly supplied RSA
public key.

At this stage, the system focuses **only on cryptographic correctness** and
implicitly assumes that the public key used for verification belongs to the
legitimate Identity Provider (IdP).

This phase establishes the **starting point** for the security analysis.

---

## Design Summary

- JWTs are signed using **RS256**
- Verification is performed using a **raw RSA public key**
- No identity binding or trust verification is enforced
- No attacker model is considered yet

This design is **functionally correct**, but **security-incomplete**.

---

## Implementation Snapshot

```python
def verify_jwt_basic(token):
    # Load RSA public key (assumed to belong to IdP)
    public_key = load_public_key(idp_public_key_path)

    # Verify JWT signature
    decoded = jwt.decode(token, public_key, algorithms=["RS256"])
    return decoded
```

---

## Security Assumptions

The system makes the following implicit assumptions:

1. The RSA public key provided to the verifier belongs to the legitimate IdP
2. The public key source has not been tampered with
3. Only the IdP possesses the corresponding private key
4. Signature validity implies issuer legitimacy

⚠️ **These assumptions are not enforced programmatically.**

---

## What Is Being Verified

| Property | Status |
|----------|--------|
| JWT Structure | ✅ Verified |
| RS256 Signature Integrity | ✅ Verified |
| Token Expiry | ✅ Verified |
| Issuer Identity | ❌ Assumed |
| Trust Anchor | ❌ Absent |

---

## Why This Is a Security Risk

The verifier has no authoritative mechanism to answer:

> **"Why should this public key be trusted?"**

Without an explicit trust model:

- Any public key could be treated as legitimate
- The verifier cannot distinguish a real IdP from an impostor
- Trust is based on configuration, not verification

At this phase, the system works, but **trust is implicit and fragile**.

---

## Security Insight

Phase 1 highlights an important distinction:

> **Signature verification guarantees integrity, not identity.**

While RS256 ensures that a token has not been altered,
it does not prove who created the token.

---

## Limitations of Phase 1

- No protection against key substitution
- No issuer authentication
- No trust anchor
- No mechanism to detect malicious key replacement

**These limitations are intentional and will be exploited in Phase 2.**

---

## Phase Boundary Clarification

- **Phase 1**: Baseline JWT verification with implicit trust
- **Phase 2**: Explicit exploitation of this trust assumption
- **Phase 3**: Introduction of a Root CA as a trust anchor

---

## Transition to Phase 2

In Phase 2, the implicit trust assumption made here is
**actively exploited** using a key substitution attack, demonstrating
why cryptographic correctness alone is insufficient for authentication.

---

## Key Takeaways

- Phase 1 establishes a functional but insecure baseline
- Trust is assumed, not verified
- Public key legitimacy is not enforced
- This phase exists to motivate the attack in Phase 2
