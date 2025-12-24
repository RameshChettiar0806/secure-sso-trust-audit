"""
Script to generate a certificate hierarchy for testing:

1. Root CA (self-signed)
2. IdP Certificate (signed by Root CA)

 FOR EDUCATIONAL/TESTING PURPOSES ONLY
Real production systems should use proper PKI infrastructure.
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
import os


def generate_root_ca():
    """
    Generate a self-signed Root CA certificate.
    
    Returns:
        Tuple of (private_key, certificate)
    """
    # Generate RSA key pair for Root CA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Build the certificate subject (who the certificate is for)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Karnataka"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Bangalore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureSSO Trust Audit"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureSSO Root CA"),
    ])
    
    # Build the certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer  # Self-signed, so issuer == subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=1),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    return private_key, cert


def generate_idp_certificate(root_ca_key, root_ca_cert):
    """
    Generate an IdP certificate signed by the Root CA.
    
    Args:
        root_ca_key: Root CA private key
        root_ca_cert: Root CA certificate
        
    Returns:
        Tuple of (private_key, certificate)
    """
    # Generate RSA key pair for IdP
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Build the certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Karnataka"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Bangalore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureSSO Identity Provider"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"secure-sso-idp"),
    ])
    
    # Build the certificate (signed by Root CA)
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        root_ca_cert.subject  # Issued by Root CA
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)  # 1 year
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(root_ca_key, hashes.SHA256(), default_backend())
    
    return private_key, cert


def save_private_key(private_key, filename):
    """Save a private key to PEM file."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as f:
        f.write(pem)
    print(f"✅ Saved: {filename}")


def save_certificate(cert, filename):
    """Save a certificate to PEM file."""
    pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(filename, 'wb') as f:
        f.write(pem)
    print(f"✅ Saved: {filename}")


def main():
    """Generate the complete certificate infrastructure."""
    
    # Create certs directory if it doesn't exist
    certs_dir = os.path.join(os.path.dirname(__file__), '..', 'certs')
    os.makedirs(certs_dir, exist_ok=True)
    
    print("🔐 Generating Certificate Infrastructure...")
    print()
    
    # 1. Generate Root CA (self-signed trust anchor)
    print("1️⃣  Generating Root CA (Trust Anchor)...")
    root_ca_key, root_ca_cert = generate_root_ca()
    save_certificate(root_ca_cert, os.path.join(certs_dir, 'root_ca.pem'))
    # Note: Root CA private key is typically NOT saved or kept extremely secure
    # We'll skip saving it as it's not needed for this demo
    print()
    
    # 2. Generate IdP Certificate (signed by Root CA)
    print("2️⃣  Generating IdP Certificate (signed by Root CA)...")
    idp_key, idp_cert = generate_idp_certificate(root_ca_key, root_ca_cert)
    save_certificate(idp_cert, os.path.join(certs_dir, 'idp_cert.pem'))
    save_private_key(idp_key, os.path.join(certs_dir, 'idp_key.pem'))
    print()
    
    print("✅ Certificate infrastructure created successfully!")
    print()
    print("📁 Generated files:")
    print(f"   - {os.path.join(certs_dir, 'root_ca.pem')}      (Root CA certificate - Trust Anchor)")
    print(f"   - {os.path.join(certs_dir, 'idp_cert.pem')}     (IdP certificate)")
    print(f"   - {os.path.join(certs_dir, 'idp_key.pem')}      (IdP private key - SECRET)")
    print()
    print("⚠️  Warning: idp_key.pem should NEVER be committed in production!")
    print("   (We commit it here for educational purposes only)")


if __name__ == '__main__':
    main()
