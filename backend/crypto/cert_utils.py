"""
Certificate utilities for X.509 certificate chain validation.

This module provides functions for:
- Loading certificates and keys
- Validating certificate chains
- Extracting public keys from certificates
- Verifying certificate signatures against a trusted Root CA
- Generating Root CA and IdP certificates
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta, timezone
from typing import Tuple
import os


def load_certificate(cert_path: str) -> x509.Certificate:
    """
    Load an X.509 certificate from a PEM file.
    
    Args:
        cert_path: Path to the certificate file
        
    Returns:
        X.509 Certificate object
    """
    with open(cert_path, 'rb') as f:
        cert_data = f.read()
    return x509.load_pem_x509_certificate(cert_data, default_backend())


def load_private_key(key_path: str):
    """
    Load a private key from a PEM file.
    
    Args:
        key_path: Path to the private key file
        
    Returns:
        Private key object
    """
    with open(key_path, 'rb') as f:
        key_data = f.read()
    return serialization.load_pem_private_key(
        key_data,
        password=None,
        backend=default_backend()
    )


def extract_public_key_from_cert(cert: x509.Certificate):
    """
    Extract the public key from an X.509 certificate.
    
    Args:
        cert: X.509 Certificate object
        
    Returns:
        Public key object
    """
    return cert.public_key()


def validate_certificate_chain(issuer_cert: x509.Certificate, 
                               root_ca_cert: x509.Certificate) -> Tuple[bool, str]:
    """
    Validate that the issuer certificate was signed by the trusted Root CA.
    
    This performs:
    1. Signature verification (cryptographic validity)
    2. Expiry validation
    3. Trust chain validation
    
    Args:
        issuer_cert: The certificate to validate (e.g., IdP certificate)
        root_ca_cert: The trusted Root CA certificate
        
    Returns:
        Tuple of (is_valid: bool, error_message: str)
    """
    try:
        # 1. Verify the issuer cert was signed by the root CA
        root_ca_public_key = root_ca_cert.public_key()
        
        # Verify the signature on the issuer certificate
        root_ca_public_key.verify(
            issuer_cert.signature,
            issuer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            issuer_cert.signature_hash_algorithm
        )
        
        # 2. Check certificate validity period
        now = datetime.now(timezone.utc)
        if now < issuer_cert.not_valid_before_utc:
            return False, "Certificate not yet valid"
        if now > issuer_cert.not_valid_after_utc:
            return False, "Certificate has expired"
        
        # 3. Verify issuer field matches root CA subject
        if issuer_cert.issuer != root_ca_cert.subject:
            return False, "Certificate issuer does not match Root CA subject"
        
        return True, "Certificate chain is valid"
        
    except Exception as e:
        return False, f"Certificate validation failed: {str(e)}"


def verify_certificate_against_root_ca(issuer_cert_path: str, 
                                      root_ca_cert_path: str) -> Tuple[bool, str]:
    """
    High-level function to verify a certificate against a trusted Root CA.
    
    Args:
        issuer_cert_path: Path to the issuer certificate
        root_ca_cert_path: Path to the Root CA certificate
        
    Returns:
        Tuple of (is_valid: bool, message: str)
    """
    issuer_cert = load_certificate(issuer_cert_path)
    root_ca_cert = load_certificate(root_ca_cert_path)
    
    return validate_certificate_chain(issuer_cert, root_ca_cert)


def verify_idp_certificate(idp_cert, root_cert):
    """
    Verify that the IdP certificate is properly signed by the Root CA.
    
    This enforces trust by validating:
    1. Issuer matches Root CA subject
    2. Signature is cryptographically valid
    3. IdP cert is not a CA (proper basic constraints)
    
    Args:
        idp_cert: IdP certificate object
        root_cert: Root CA certificate object
        
    Returns:
        True if validation succeeds
        
    Raises:
        Exception if validation fails
    """
    # 1. Verify issuer
    if idp_cert.issuer != root_cert.subject:
        raise Exception("IdP certificate issuer mismatch")

    # 2. Verify signature
    root_public_key = root_cert.public_key()
    root_public_key.verify(
        idp_cert.signature,
        idp_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        idp_cert.signature_hash_algorithm,
    )

    # 3. Basic constraints check
    bc = idp_cert.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value

    if bc.ca:
        raise Exception("IdP certificate must not be a CA")

    return True


def generate_root_ca():
    """
    Generate a self-signed Root CA certificate.
    
    Returns:
        Tuple of (private_key, certificate)
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Bangalore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureSSO Trust Audit"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureSSO Root CA"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    return key, cert


def generate_idp_cert(root_key, root_cert):
    """
    Generate an IdP certificate signed by the Root CA.
    
    Args:
        root_key: Root CA private key
        root_cert: Root CA certificate
        
    Returns:
        Tuple of (private_key, certificate)
    """
    idp_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Bangalore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureSSO Identity Provider"),
        x509.NameAttribute(NameOID.COMMON_NAME, "secure-sso-idp"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(idp_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    return idp_key, cert


def save_pem(obj, path, is_private=False):
    """
    Save a key or certificate to a PEM file.
    
    Args:
        obj: Key or certificate object to save
        path: File path to save to
        is_private: Whether this is a private key (True) or certificate/public key (False)
    """
    with open(path, "wb") as f:
        if is_private:
            f.write(
                obj.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        else:
            f.write(obj.public_bytes(serialization.Encoding.PEM))


def get_public_key_from_cert(cert_path):
    """Extract public key from certificate"""
    cert = load_certificate(cert_path)
    return cert.public_key()

def get_certificate_info(cert_path):
    """Get detailed info about a certificate"""
    cert = load_certificate(cert_path)
    return {
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'serial_number': cert.serial_number,
        'not_valid_before': cert.not_valid_before,
        'not_valid_after': cert.not_valid_after,
        'is_ca': False,  # Check if it's a CA certificate
        'signature_algorithm': str(cert.signature_algorithm_oid)
    }

def create_self_signed_cert(private_key, subject_name, days_valid=365):
    """Create a self-signed certificate (for testing)"""
    from cryptography.x509.oid import NameOID
    import datetime
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
    ).sign(private_key, hashes.SHA256(), backend=default_backend())
    
    return cert

def save_certificate(cert, path):
    """Save certificate to PEM file"""
    pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(path, 'wb') as f:
        f.write(pem)
