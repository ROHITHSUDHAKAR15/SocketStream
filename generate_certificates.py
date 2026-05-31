#!/usr/bin/env python3
"""
Generate self-signed SSL certificates for the Secure Messaging System
"""

import os
import subprocess
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone

def generate_self_signed_cert():
    """Generate a self-signed SSL certificate"""
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Messaging System"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
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
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress("127.0.0.1"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # Write private key to file
    with open("server.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write certificate to file
    with open("server.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("✅ SSL certificates generated successfully!")
    print("📁 Files created:")
    print("   - server.key (private key)")
    print("   - server.crt (certificate)")
    print("\n⚠️  Note: These are self-signed certificates for development only.")
    print("   For production, use certificates from a trusted Certificate Authority.")

def check_openssl():
    """Check if OpenSSL is available"""
    try:
        subprocess.run(["openssl", "version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def generate_with_openssl():
    """Generate certificates using OpenSSL command line"""
    try:
        # Generate private key
        subprocess.run([
            "openssl", "genrsa", "-out", "server.key", "2048"
        ], check=True)
        
        # Generate certificate signing request
        subprocess.run([
            "openssl", "req", "-new", "-key", "server.key", "-out", "server.csr",
            "-subj", "/C=US/ST=California/L=San Francisco/O=Secure Messaging System/CN=localhost"
        ], check=True)
        
        # Generate self-signed certificate
        subprocess.run([
            "openssl", "x509", "-req", "-in", "server.csr", "-signkey", "server.key",
            "-out", "server.crt", "-days", "365"
        ], check=True)
        
        # Clean up CSR file
        os.remove("server.csr")
        
        print("✅ SSL certificates generated successfully using OpenSSL!")
        print("📁 Files created:")
        print("   - server.key (private key)")
        print("   - server.crt (certificate)")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error generating certificates with OpenSSL: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False
    
    return True

def main():
    print("🔐 Generating SSL certificates for Secure Messaging System...")
    print()
    
    # Check if certificates already exist
    if os.path.exists("server.key") and os.path.exists("server.crt"):
        print("⚠️  SSL certificates already exist!")
        response = input("Do you want to regenerate them? (y/N): ")
        if response.lower() != 'y':
            print("Keeping existing certificates.")
            return
    
    # Try to use OpenSSL first (more standard)
    if check_openssl():
        print("🔧 Using OpenSSL to generate certificates...")
        if generate_with_openssl():
            return
    
    # Fallback to Python cryptography library
    print("🔧 Using Python cryptography library to generate certificates...")
    try:
        generate_self_signed_cert()
    except Exception as e:
        print(f"❌ Error generating certificates: {e}")
        print("\n💡 Make sure you have the required dependencies installed:")
        print("   pip install cryptography")
        sys.exit(1)

if __name__ == "__main__":
    main() 