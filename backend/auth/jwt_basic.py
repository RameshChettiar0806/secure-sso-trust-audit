# NOTE:
# This verification only checks cryptographic validity.
# It does NOT establish issuer trust or identity.

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
from datetime import datetime, timedelta, timezone


def generate_rsa_keypair():
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


def create_jwt(private_key_pem):
    payload = {
        "sub": "user123",
        "role": "user",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5)
    }

    token = jwt.encode(
        payload,
        private_key_pem,
        algorithm="RS256"
    )
    return token


def verify_jwt(token, public_key_pem):
    # NOTE:
    # This verifies cryptographic integrity ONLY.
    # It does NOT establish issuer trust.
    return jwt.decode(
        token,
        public_key_pem,
        algorithms=["RS256"]
    )
