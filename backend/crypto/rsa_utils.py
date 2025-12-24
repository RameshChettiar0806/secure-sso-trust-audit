"""
RSA utility functions for key loading and JWT operations
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

def load_private_key(key_path, password=None):
    """Load a private key from PEM file"""
    with open(key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
            backend=default_backend()
        )
    return private_key

def load_public_key(cert_or_key_path):
    """Load a public key from PEM certificate or public key file"""
    with open(cert_or_key_path, 'rb') as key_file:
        try:
            # Try loading as certificate first
            from cryptography.x509 import load_pem_x509_certificate
            cert = load_pem_x509_certificate(
                key_file.read(),
                backend=default_backend()
            )
            return cert.public_key()
        except Exception:
            # If that fails, try as public key
            key_file.seek(0)
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
            return public_key

def generate_rsa_keypair(key_size=2048):
    """Generate a new RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def save_private_key(private_key, path):
    """Save private key to PEM file"""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(path, 'wb') as f:
        f.write(pem)

def save_public_key(public_key, path):
    """Save public key to PEM file"""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(path, 'wb') as f:
        f.write(pem)
