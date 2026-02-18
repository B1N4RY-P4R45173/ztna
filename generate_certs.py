#!/usr/bin/env python3
"""
Certificate Generator for Controller-Gateway mTLS
Updated to use timezone-aware UTC datetimes.
"""

import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os

def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

def save_key(key, filepath):
    # Ensure the parent directory exists
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filepath, 'wb') as f:
        f.write(pem)
    os.chmod(filepath, 0o600)
    print(f"✓ {filepath}")

def save_cert(cert, filepath):
    # Ensure the parent directory exists
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"✓ {filepath}")

print("\n" + "="*60)
print("Generating mTLS Certificates")
print("="*60 + "\n")

# Use timezone-aware UTC for modern Python compliance
now = datetime.datetime.now(datetime.timezone.utc)
expiry = now + datetime.timedelta(days=365)

# Step 1: Create CA
print("[1/3] Creating CA...")
ca_key = generate_key()
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SDP-CA")])

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(expiry)
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(
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
    )
    .sign(ca_key, hashes.SHA256(), default_backend())
)

save_key(ca_key, "ca_key.pem")
save_cert(ca_cert, "ca_cert.pem")

# Step 2: Controller certificate
print("\n[2/3] Creating Controller certificate...")
controller_key = generate_key()
controller_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sdp-controller")])

controller_cert = (
    x509.CertificateBuilder()
    .subject_name(controller_name)
    .issuer_name(ca_name)
    .public_key(controller_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(expiry)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
        critical=True,
    )
    .sign(ca_key, hashes.SHA256(), default_backend())
)

save_key(controller_key, "sdp_controller/controller_key.pem")
save_cert(controller_cert, "sdp_controller/controller_cert.pem")
save_cert(ca_cert, "sdp_controller/ca_cert.pem")

# Step 3: Gateway certificate
print("\n[3/3] Creating Gateway certificate...")
gateway_key = generate_key()
gateway_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sdp-gateway")])

gateway_cert = (
    x509.CertificateBuilder()
    .subject_name(gateway_name)
    .issuer_name(ca_name)
    .public_key(gateway_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(expiry)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
        critical=True,
    )
    .sign(ca_key, hashes.SHA256(), default_backend())
)

save_key(gateway_key, "sdp_gateway/gateway_key.pem")
save_cert(gateway_cert, "sdp_gateway/gateway_cert.pem")
save_cert(ca_cert, "sdp_gateway/ca_cert.pem")

print("\n" + "="*60)
print("✓ Certificate generation complete!")
print("="*60)
print("\nCertificates valid for 1 year")
print("\nNext steps:")
print("  1. Start Gateway: python3 mtls_gateway.py")
print("  2. Start Controller: python3 mtls_controller.py")
print("="*60 + "\n")