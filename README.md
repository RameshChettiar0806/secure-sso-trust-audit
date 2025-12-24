# Secure SSO Trust Audit

An educational project demonstrating JWT security vulnerabilities and their fixes through progressive security phases.

## Project Overview

This project implements a phased approach to understanding JWT (JSON Web Token) security in Single Sign-On (SSO) systems:

- **Phase 1**: Baseline JWT authentication with raw RSA (no trust validation)
- **Phase 2**: Trust failure demonstration (key substitution attack)
- **Phase 3**: Understanding the attack vector
- **Phase 4**: Secure implementation with certificate chain validation

## Phase 2 – Trust Failure Demonstration

This phase demonstrates that validating RS256 JWT signatures alone
is insufficient for authentication.

A key substitution attack is used to show that tokens signed by an
untrusted issuer are accepted when no trust anchor exists.

This phase intentionally contains a vulnerability to motivate the
introduction of certificate-based trust in Phase 3.

## Project Structure

```
secure-sso-trust-audit/
├── backend/
│   ├── app.py                 # Flask API
│   ├── auth/
│   │   ├── jwt_basic.py       # Phase 2: Basic RSA (vulnerable)
│   │   ├── jwt_cert.py        # Phase 4: Certificate-based (secure)
│   ├── crypto/
│   │   ├── rsa_utils.py       # RSA key utilities
│   │   ├── cert_utils.py      # Certificate validation
│   ├── certs/                 # X.509 certificates and keys
│   ├── requirements.txt
│
├── docs/
│   ├── phase1_basic_rsa.md
│   ├── phase2_attack.md
│   ├── phase3_cert_fix.md
│
└── README.md
```

## Setup

### 1. Create Virtual Environment

```bash
cd backend
python -m venv venv
venv\Scripts\activate  # On Windows
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Generate Certificates (if needed)

Use the provided scripts to generate test certificates and keys.

### 4. Run the Flask Server

```bash
python app.py
```

The server will run on `http://localhost:5000`

## API Endpoints

### Health Check
```
GET /health
```

### Phase 2: Basic JWT Verification (Vulnerable)
```
POST /verify/phase2
Content-Type: application/json

{
  "token": "<JWT_TOKEN>"
}
```

### Phase 4: Secure JWT Verification
```
POST /verify/phase4
Content-Type: application/json

{
  "token": "<JWT_TOKEN>"
}
```

## Key Concepts

### Phase 2 Vulnerability
The basic RSA verification trusts any JWT signed with a key that matches the public key. An attacker can:
1. Generate their own RSA key pair
2. Create a malicious JWT
3. If the system trusts the attacker's public key, the JWT will be verified successfully

### Phase 4 Solution
Certificate chain validation ensures:
1. The IdP's certificate is signed by a trusted Root CA
2. Only certificates from trusted issuers are accepted
3. Key substitution attacks are prevented

## Files

- `app.py` - Flask application with JWT verification endpoints
- `auth/jwt_basic.py` - Phase 2 implementation (vulnerable)
- `auth/jwt_cert.py` - Phase 4 implementation (secure)
- `crypto/rsa_utils.py` - RSA key handling
- `crypto/cert_utils.py` - X.509 certificate validation
- `certs/` - Test certificates and keys

## Dependencies

- Flask - Web framework
- PyJWT - JWT encoding/decoding
- cryptography - Cryptographic operations
- requests - HTTP client

## Documentation

See the `docs/` folder for detailed phase descriptions and attack vectors.

## License

Educational purposes only.
