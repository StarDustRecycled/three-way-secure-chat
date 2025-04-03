#!/usr/bin/env python3
import os
import json
import base64
import hashlib
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

CERTS_DIR = Path("certs")

def load_certificate(entity_name):
    """Load certificate for an entity"""
    cert_path = CERTS_DIR / f"{entity_name.lower()}_cert.json"
    with open(cert_path, "r") as f:
        return json.load(f)

def load_private_key(entity_name):
    """Load private key for an entity"""
    key_path = CERTS_DIR / f"{entity_name.lower()}_private.pem"
    with open(key_path, "rb") as f:
        return RSA.import_key(f.read())

def verify_certificate(cert, issuer_cert):
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
        return True
    except (ValueError, TypeError):
        return False

def generate_nonce(size=32):
    """Generate a random nonce"""
    return get_random_bytes(size)

def increment_nonce(nonce_bytes):
    """Increment a nonce by 1 (for challenge-response)"""
    # Convert to integer, increment, and convert back to bytes
    nonce_int = int.from_bytes(nonce_bytes, byteorder='big')
    nonce_int += 1
    return nonce_int.to_bytes(len(nonce_bytes), byteorder='big')

def decrypt_nonce(encrypted_nonce, private_key):
    """Decrypt a nonce using entity's private key"""
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_nonce)

def encrypt_with_public_key(data, public_key_str):
    """Encrypt data using entity's public key"""
    public_key = RSA.import_key(public_key_str)
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

def hash_data(data):
    """Generate SHA-256 hash of data"""
    return SHA256.new(data)

def sign_data(data, private_key):
    """Sign data using entity's private key"""
    h = hash_data(data)
    signer = pkcs1_15.new(private_key)
    return signer.sign(h)

def verify_signature(data, signature, public_key_str):
    """Verify signature using entity's public key"""
    h = hash_data(data)
    public_key = RSA.import_key(public_key_str)
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def derive_shared_key(na, nb, nc):
    """Derive shared key from nonces"""
    combined = na + nb + nc
    return hashlib.sha256(combined).digest()

def save_shared_key(key):
    """Save the derived shared key"""
    key_data = {
        "key": base64.b64encode(key).decode('utf-8'),
        "created": json.loads(open(CERTS_DIR / "shared_key.json").read())["created"],
        "expiry": json.loads(open(CERTS_DIR / "shared_key.json").read())["expiry"]
    }
    
    with open(CERTS_DIR / "shared_key.json", "w") as f:
        json.dump(key_data, f, indent=4)

def load_shared_key():
    """Load the shared key"""
    with open(CERTS_DIR / "shared_key.json", "r") as f:
        key_data = json.load(f)
        if key_data["key"]:
            return base64.b64decode(key_data["key"])
        return None

def encrypt_message(message, shared_key):
    """Encrypt a message using AES-GCM with the shared key"""
    # Generate a random nonce for AES-GCM
    nonce = get_random_bytes(12)
    
    # Convert message to bytes if it's a string
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Create cipher object and encrypt
    cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    
    # Return a dictionary with all components needed for decryption
    return {
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8')
    }

def decrypt_message(encrypted_msg, shared_key):
    """Decrypt a message using AES-GCM with the shared key"""
    # Extract components
    ciphertext = base64.b64decode(encrypted_msg["ciphertext"])
    nonce = base64.b64decode(encrypted_msg["nonce"])
    tag = base64.b64decode(encrypted_msg["tag"])
    
    # Create cipher object and decrypt
    cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    # Return the plaintext (assuming it's UTF-8 encoded)
    return plaintext.decode('utf-8')

def prepare_nonce_message(nonce, recipient_entity, sender_entity):
    """Prepare a nonce message for sending to another entity"""
    # Load recipient's certificate to get public key
    recipient_cert = load_certificate(recipient_entity)
    recipient_public_key = recipient_cert["public_key"]
    
    # Encrypt nonce with recipient's public key
    encrypted_nonce = encrypt_with_public_key(nonce, recipient_public_key)
    
    # Hash the encrypted nonce
    hashed_nonce = hash_data(encrypted_nonce).digest()
    
    # Sign the hash with sender's private key
    sender_private_key = load_private_key(sender_entity)
    signature = sign_data(hashed_nonce, sender_private_key)
    
    # Prepare the message
    message = {
        "encrypted_nonce": base64.b64encode(encrypted_nonce).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8'),
        "sender": sender_entity,
        "recipient": recipient_entity
    }
    
    return message

def verify_nonce_message(message, server_cert=None):
    """Verify a nonce message"""
    encrypted_nonce = base64.b64decode(message["encrypted_nonce"])
    signature = base64.b64decode(message["signature"])
    sender = message["sender"]
    
    # If server signature is provided, verify it
    if server_cert:
        hashed_nonce = hash_data(encrypted_nonce).digest()
        server_public_key = server_cert["public_key"]
        if not verify_signature(hashed_nonce, signature, server_public_key):
            return False, None
    
    # Decrypt nonce with own private key
    private_key = load_private_key(message["recipient"])
    try:
        nonce = decrypt_nonce(encrypted_nonce, private_key)
        return True, nonce
    except Exception:
        return False, None

def sign_server_message(message):
    """Sign a message as the server"""
    # Load server's private key
    server_private_key = load_private_key("S")
    
    # Extract the encrypted nonce
    encrypted_nonce = base64.b64decode(message["encrypted_nonce"])
    
    # Hash the encrypted nonce
    hashed_nonce = hash_data(encrypted_nonce).digest()
    
    # Sign the hash
    signature = sign_data(hashed_nonce, server_private_key)
    
    # Update the message with server's signature
    message["signature"] = base64.b64encode(signature).decode('utf-8')
    message["verified_by"] = "S"
    
    return message