"""
Phase 4: Secure JWT verification with certificate chain validation.

This module enforces trust by:
1. Validating the IdP certificate against the Root CA
2. Only using public keys from validated certificates
3. Rejecting tokens from untrusted issuers
"""

import jwt
from datetime import datetime, timedelta, timezone
from crypto.cert_utils import (
    load_certificate,
    load_private_key,
    verify_idp_certificate,
)

ROOT_CA_PATH = "certs/root_ca.pem"
IDP_CERT_PATH = "certs/idp_cert.pem"
IDP_KEY_PATH = "certs/idp_key.pem"


def create_jwt_with_cert():
    """
    Create a JWT signed with the IdP's private key from the certificate.
    
    Returns:
        JWT token string
    """
    # Load the IdP's private key
    private_key = load_private_key(IDP_KEY_PATH)
    
    # Create JWT payload
    payload = {
        "sub": "user123",
        "role": "user",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=1)
    }
    
    # Sign with IdP's private key
    token = jwt.encode(payload, private_key, algorithm="RS256")
    
    return token


def verify_jwt_with_cert(token):
    """
    Verify a JWT token using certificate chain validation.
    
    This is the secure Phase 4 implementation that prevents
    key substitution attacks by enforcing certificate trust.
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded JWT payload
        
    Raises:
        Exception if certificate validation fails
        jwt.InvalidTokenError if JWT verification fails
    """
    # Load certificates
    root_cert = load_certificate(ROOT_CA_PATH)
    idp_cert = load_certificate(IDP_CERT_PATH)

    # Enforce trust - this will raise an exception if validation fails
    verify_idp_certificate(idp_cert, root_cert)

    # Extract trusted public key (only reached if cert is valid)
    trusted_public_key = idp_cert.public_key()

    # Verify JWT with the trusted public key
    payload = jwt.decode(
        token,
        trusted_public_key,
        algorithms=["RS256"]
    )

    return payload

