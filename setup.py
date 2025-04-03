#!/usr/bin/env python3
import os
import json
import hashlib
import argparse
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from pathlib import Path

class CertificateAuthority:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.certs_dir = Path("certs")
        self.certs_dir.mkdir(exist_ok=True)
        
    def generate_root_ca(self):
        """Generate a self-signed root CA certificate and private key"""
        print("Generating Root CA key pair...")
        
        # Generate RSA key pair for root CA
        root_key = RSA.generate(self.key_size)
        root_private_key = root_key.export_key()
        root_public_key = root_key.publickey().export_key()
        
        # Save private key
        with open(self.certs_dir / "root_ca_private.pem", "wb") as f:
            f.write(root_private_key)
        
        # Generate self-signed certificate
        root_cert = {
            "subject": "Root CA",
            "issuer": "Root CA",
            "public_key": root_public_key.decode('utf-8'),
            "serial_number": 1,
            "not_before": datetime.now().isoformat(),
            "not_after": (datetime.now() + timedelta(days=3650)).isoformat(),  # 10 years validity
            "extensions": {
                "key_usage": ["cert_sign", "crl_sign"],
                "basic_constraints": {
                    "ca": True,
                    "path_length": 1
                }
            }
        }
        
        # Create certificate data to sign
        cert_data = json.dumps(root_cert, sort_keys=True).encode('utf-8')
        cert_hash = SHA256.new(cert_data)
        
        # Self-sign the certificate
        signer = pkcs1_15.new(RSA.import_key(root_private_key))
        signature = signer.sign(cert_hash)
        
        # Add signature to certificate
        root_cert["signature"] = signature.hex()
        root_cert["signature_algorithm"] = "sha256WithRSAEncryption"
        
        # Save certificate
        with open(self.certs_dir / "root_ca_cert.json", "w") as f:
            json.dump(root_cert, f, indent=4)
            
        print(f"Root CA certificate and private key generated successfully in {self.certs_dir}")
        return root_cert, root_private_key
    
    def generate_entity_certificate(self, entity_name, root_cert, root_private_key):
        """Generate a certificate for an entity signed by the root CA"""
        print(f"Generating certificate for {entity_name}...")
        
        # Generate RSA key pair for the entity
        entity_key = RSA.generate(self.key_size)
        entity_private_key = entity_key.export_key()
        entity_public_key = entity_key.publickey().export_key()
        
        # Save private key
        with open(self.certs_dir / f"{entity_name.lower()}_private.pem", "wb") as f:
            f.write(entity_private_key)
        
        # Create certificate
        entity_cert = {
            "subject": entity_name,
            "issuer": "Root CA",
            "public_key": entity_public_key.decode('utf-8'),
            "serial_number": hash(entity_name) % 1000000 + 2,  # Simple way to generate a unique serial
            "not_before": datetime.now().isoformat(),
            "not_after": (datetime.now() + timedelta(days=365)).isoformat(),  # 1 year validity
            "extensions": {
                "key_usage": ["digital_signature", "key_encipherment"],
                "basic_constraints": {
                    "ca": False
                }
            }
        }
        
        # Create certificate data to sign
        cert_data = json.dumps(entity_cert, sort_keys=True).encode('utf-8')
        cert_hash = SHA256.new(cert_data)
        
        # Sign the certificate with root CA's private key
        signer = pkcs1_15.new(RSA.import_key(root_private_key))
        signature = signer.sign(cert_hash)
        
        # Add signature to certificate
        entity_cert["signature"] = signature.hex()
        entity_cert["signature_algorithm"] = "sha256WithRSAEncryption"
        
        # Save certificate
        with open(self.certs_dir / f"{entity_name.lower()}_cert.json", "w") as f:
            json.dump(entity_cert, f, indent=4)
            
        print(f"Certificate for {entity_name} generated successfully")
        return entity_cert, entity_private_key
    
    def verify_certificate(self, cert, issuer_cert):
        """Verify a certificate using the issuer's certificate"""
        # Create a copy of the certificate without the signature for verification
        cert_copy = cert.copy()
        signature = bytes.fromhex(cert_copy.pop("signature"))
        signature_algorithm = cert_copy.pop("signature_algorithm", None)
        
        # Hash the certificate data
        cert_data = json.dumps(cert_copy, sort_keys=True).encode('utf-8')
        cert_hash = SHA256.new(cert_data)
        
        # Verify the signature using the issuer's public key
        issuer_public_key = RSA.import_key(issuer_cert["public_key"])
        verifier = pkcs1_15.new(issuer_public_key)
        
        try:
            verifier.verify(cert_hash, signature)
            print(f"Certificate for {cert['subject']} verified successfully")
            return True
        except (ValueError, TypeError) as e:
            print(f"Certificate verification failed: {e}")
            return False

def load_certificate(cert_path):
    """Load a certificate from a file"""
    with open(cert_path, "r") as f:
        return json.load(f)

def validate_all_certificates(ca):
    """Validate all generated certificates"""
    print("\nValidating certificates...")
    
    # Load root CA certificate
    root_cert = load_certificate(ca.certs_dir / "root_ca_cert.json")
    
    # Validate root CA certificate (self-signed)
    if not ca.verify_certificate(root_cert, root_cert):
        print("Root CA certificate validation failed")
        return False
    
    # Validate entity certificates
    for entity in ["A", "B", "C", "S"]:
        entity_cert = load_certificate(ca.certs_dir / f"{entity.lower()}_cert.json")
        if not ca.verify_certificate(entity_cert, root_cert):
            print(f"Certificate for {entity} validation failed")
            return False
    
    print("All certificates validated successfully")
    return True

def generate_empty_shared_key_file(ca):
    """Generate an empty shared key file that will be populated during key exchange"""
    shared_key_file = ca.certs_dir / "shared_key.json"
    shared_key_data = {
        "key": None,
        "created": datetime.now().isoformat(),
        "expiry": (datetime.now() + timedelta(days=1)).isoformat()
    }
    
    with open(shared_key_file, "w") as f:
        json.dump(shared_key_data, f, indent=4)
    
    print(f"Empty shared key file created at {shared_key_file}")

def main():
    parser = argparse.ArgumentParser(description="Setup script for secure three-way chat system")
    parser.add_argument("--force", action="store_true", help="Force regeneration of certificates")
    args = parser.parse_args()
    
    ca = CertificateAuthority()
    
    # Check if certificates already exist
    if ca.certs_dir.exists() and list(ca.certs_dir.glob("*.json")) and list(ca.certs_dir.glob("*.pem")) and not args.force:
        print("Certificates already exist. Use --force to regenerate.")
        try:
            validate_all_certificates(ca)
        except FileNotFoundError:
            print("Some certificate files are missing. Use --force to regenerate all certificates.")
        return
    
    # Generate root CA
    root_cert, root_private_key = ca.generate_root_ca()
    
    # Generate certificates for A, B, C, and S
    for entity in ["A", "B", "C", "S"]:
        ca.generate_entity_certificate(entity, root_cert, root_private_key)
    
    # Validate all certificates
    validate_all_certificates(ca)
    
    # Generate empty shared key file
    generate_empty_shared_key_file(ca)
    
    print("\nSetup completed successfully. The system is ready for nonce exchange.")

if __name__ == "__main__":
    main()