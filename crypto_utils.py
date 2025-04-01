from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import json
import base64

class Certificate:
    """
    Simplified certificate class for entities
    Represents CA<<A>>, CA<<B>>, CA<<C>>, CA<<S>>
    """
    def __init__(self, entity_id, public_key):
        self.entity_id = entity_id
        self.public_key = public_key
    
    def serialize(self):
        """Convert certificate to serializable format"""
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return {
            'entity_id': self.entity_id,
            'public_key': base64.b64encode(public_bytes).decode('utf-8')
        }
    
    @classmethod
    def deserialize(cls, data):
        """Create certificate from serialized format"""
        public_bytes = base64.b64decode(data['public_key'].encode('utf-8'))
        public_key = serialization.load_pem_public_key(
            public_bytes,
            backend=default_backend()
        )
        return cls(data['entity_id'], public_key)
    
    def __str__(self):
        return f"Certificate[{self.entity_id}]"

def generate_key_pair():
    """Generate RSA key pair for an entity"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_key_pair(private_key, entity_id):
    """Save private key to file"""
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"{entity_id.lower()}_private_key.pem", "wb") as f:
        f.write(private_bytes)

def load_private_key(entity_id):
    """Load private key from file"""
    with open(f"{entity_id.lower()}_private_key.pem", "rb") as f:
        private_bytes = f.read()
    return serialization.load_pem_private_key(
        private_bytes,
        password=None,
        backend=default_backend()
    )

def encrypt_with_public_key(public_key, message):
    """
    Encrypt message using recipient's public key (Kb, Kc)
    Used for: {Na}Kb, {Na}Kc
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_with_private_key(private_key, ciphertext):
    """
    Decrypt message using own private key (Ka-1, Kb-1, Kc-1)
    Used for: {Na}Kb -> Na (when B uses Kb-1)
    """
    ciphertext_bytes = base64.b64decode(ciphertext.encode('utf-8'))
    
    plaintext = private_key.decrypt(
        ciphertext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def calculate_hash(data):
    """
    Calculate hash of data
    Used for: H({Na}Kb, {Na}Kc)
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif isinstance(data, dict) or isinstance(data, list):
        data = json.dumps(data, sort_keys=True).encode('utf-8')
    
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return base64.b64encode(digest.finalize()).decode('utf-8')

def sign_data(private_key, data):
    """
    Sign data using private key
    Used for: {H({Na}Kb, {Na}Kc)}Ka-1
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key, data, signature):
    """
    Verify signature using public key
    Used for verifying: {H({Na}Kb, {Na}Kc)}Ka-1
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    signature_bytes = base64.b64decode(signature.encode('utf-8'))
    
    try:
        public_key.verify(
            signature_bytes,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def generate_nonce():
    """
    Generate random nonce
    Used for: Na, Nb, Nc
    """
    return os.urandom(16)

def decrement_nonce(nonce):
    """
    Decrement nonce by 1 (for acknowledgment)
    Used for: Na-1, Nb-1, Nc-1
    """
    nonce_array = bytearray(nonce)
    # Decrement last byte by 1
    if nonce_array[-1] > 0:
        nonce_array[-1] -= 1
    else:
        # If last byte is 0, wrap around to 255
        nonce_array[-1] = 255
    return bytes(nonce_array)

def derive_session_key(na, nb, nc):
    """
    Derive the session key from the three nonces
    Kabc = H(Na || Nb || Nc)
    """
    combined = na + nb + nc
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(combined)
    return digest.finalize()

def encrypt_message(session_key, message):
    """
    Encrypt a message with the session key
    Used for: {M1}Kabc
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Generate a random IV
    iv = os.urandom(16)
    
    # Create an encryptor object
    cipher = Cipher(
        algorithms.AES(session_key[:32]),
        modes.CFB(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Encrypt the message
    ciphertext = encryptor.update(message) + encryptor.finalize()
    
    # Return IV and ciphertext
    result = {
        'iv': base64.b64encode(iv).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }
    return json.dumps(result)

def decrypt_message(session_key, encrypted_message):
    """
    Decrypt a message with the session key
    Used for decrypting: {M1}Kabc
    """
    try:
        data = json.loads(encrypted_message)
        iv = base64.b64decode(data['iv'].encode('utf-8'))
        ciphertext = base64.b64decode(data['ciphertext'].encode('utf-8'))
        
        # Create a decryptor object
        cipher = Cipher(
            algorithms.AES(session_key[:32]),
            modes.CFB(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt the message
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except Exception as e:
        print(f"Error decrypting message: {e}")
        return None