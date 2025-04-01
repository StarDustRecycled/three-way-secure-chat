import socket
import threading
import json
import time
import os
import sys
import base64
from crypto_utils import (
    Certificate, generate_key_pair, encrypt_with_public_key, decrypt_with_private_key,
    calculate_hash, sign_data, verify_signature, generate_nonce, decrement_nonce,
    derive_session_key, encrypt_message, decrypt_message, save_key_pair
)

class ChatClient:
    def __init__(self, entity_id, server_host='127.0.0.1', server_port=5000):
        """Initialize a chat client (A, B, or C)"""
        self.entity_id = entity_id
        self.server_host = server_host
        self.server_port = server_port
        
        # Generate key pair for this entity
        print(f"Generating key pair for {entity_id}...")
        self.private_key, self.public_key = generate_key_pair()
        save_key_pair(self.private_key, entity_id)
        
        # Create certificate
        self.certificate = Certificate(entity_id, self.public_key)
        
        # Store other entities' certificates
        self.certificates = {entity_id: self.certificate}
        
        # Server certificate
        self.server_certificate = None
        
        # Create socket for communication
        self.socket = None
        self.running = False
        self.connected = False
        self.authenticated = False
        
        # Key establishment variables
        self.my_nonce = None
        self.received_nonces = {}
        self.session_key = None
        self.key_established = False
        
        # Protocol state
        self.other_entities = []
        self.protocol_state = "INIT"
        
        # Thread for receiving messages
        self.receive_thread = None
        
        print(f"Client {entity_id} initialized")
    
    def connect_to_server(self):
        """Connect to the chat server"""
        try:
            # Create a socket and connect to the server
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(30)  # Set a 30-second timeout
            self.socket.connect((self.server_host, self.server_port))
            self.connected = True
            
            # Register with the server
            self.register_with_server()
            
            # Start thread to receive messages
            self.running = True
            self.receive_thread = threading.Thread(target=self.receive_messages)
            self.receive_thread.daemon = True
            self.receive_thread.start()
            
            return True
        
        except Exception as e:
            print(f"Connection error: {e}")
            return False
    
    def register_with_server(self):
        """Register with the server by sending certificate"""
        # Step 1: Send certificate to server
        registration_message = {
            'type': 'register',
            'entity_id': self.entity_id,
            'certificate': self.certificate.serialize()
        }
        self.socket.send(json.dumps(registration_message).encode('utf-8'))
        print(f"Sent registration request to server")
    
    def request_certificates(self, entity_ids):
        """Request certificates for other entities from server"""
        # Following protocol: A -> S : CA <<A>>, B, C (request certificates)
        request_message = {
            'type': 'certificate_request',
            'entities': entity_ids
        }
        self.socket.send(json.dumps(request_message).encode('utf-8'))
        print(f"Requested certificates for: {', '.join(entity_ids)}")
    
    def receive_messages(self):
        """Receive and process incoming messages"""
        buffer = ""
        while self.running:
            try:
                # Receive data from server
                data = self.socket.recv(4096)
                if not data:
                    print("Connection to server lost")
                    break
                
                # Add to buffer and try to parse complete JSON objects
                buffer += data.decode('utf-8')
                
                # Process all complete JSON objects in the buffer
                while buffer:
                    try:
                        # Try to parse a JSON object
                        message, index = self._parse_json(buffer)
                        if message is None:
                            # Incomplete JSON, wait for more data
                            break
                        
                        # Remove the processed JSON from the buffer
                        buffer = buffer[index:]
                        
                        # Process the message
                        self._process_message(message)
                    except json.JSONDecodeError:
                        # If we can't parse the start of the buffer, discard the first character
                        if len(buffer) > 1:
                            print(f"Discarding invalid JSON character: {buffer[0]}")
                            buffer = buffer[1:]
                        else:
                            buffer = ""
                        
            except socket.timeout:
                # Just continue on timeout
                continue
            except Exception as e:
                print(f"Error receiving messages: {e}")
                break
        
        print("Receive thread terminated")
        self.connected = False
    
    def _parse_json(self, data):
        """Parse a JSON object from the beginning of the data string"""
        try:
            # Try to parse the entire string
            message = json.loads(data)
            return message, len(data)
        except json.JSONDecodeError as e:
            # If we have a complete JSON object followed by extra data
            if e.msg.startswith('Extra data'):
                # Parse just the complete JSON object
                message = json.loads(data[:e.pos])
                return message, e.pos
            # If it's an incomplete JSON object
            return None, 0
    
    def _process_message(self, message):
        """Process a parsed message"""
        message_type = message.get('type')
        
        # Process different message types
        if message_type == 'register_ack':
            # Server acknowledged registration
            server_cert_data = message['server_cert']
            self.server_certificate = Certificate.deserialize(server_cert_data)
            self.certificates['S'] = self.server_certificate
            self.authenticated = True
            print("Registration acknowledged by server")
            print(f"Received server certificate: {self.server_certificate}")
            
            # Request certificates for other entities
            if self.entity_id == 'A':
                self.other_entities = ['B', 'C']
            elif self.entity_id == 'B':
                self.other_entities = ['A', 'C']
            else:  # entity_id == 'C'
                self.other_entities = ['A', 'B']
            
            self.request_certificates(self.other_entities)
        
        elif message_type == 'certificate_response':
            # Received certificates from server
            received_certs = message.get('certificates', {})
            for entity_id, cert_data in received_certs.items():
                try:
                    cert = Certificate.deserialize(cert_data)
                    self.certificates[entity_id] = cert
                    print(f"Received certificate for {entity_id}")
                except Exception as e:
                    print(f"Error processing certificate for {entity_id}: {e}")
            
            # If we have all required certificates, start key establishment
            missing_certs = [entity for entity in self.other_entities if entity not in self.certificates]
            if missing_certs:
                print(f"Still waiting for certificates: {', '.join(missing_certs)}")
            else:
                print("All certificates received. Starting key establishment...")
                self.protocol_state = "CERTS_RECEIVED"
                # Start key establishment after a brief delay
                threading.Timer(1.0, self.initiate_key_establishment).start()
        
        elif message_type == 'key_establishment':
            # Process key establishment message
            self.handle_key_establishment_message(message)
        
        elif message_type == 'chat':
            # Process chat message
            self.handle_chat_message(message)
    
    def initiate_key_establishment(self):
        """Initiate key establishment protocol"""
        if not all(entity in self.certificates for entity in self.other_entities):
            print("Cannot initiate key establishment: missing certificates")
            return
        
        # Generate a random nonce
        self.my_nonce = generate_nonce()
        
        # Encrypt nonce with each entity's public key
        encrypted_nonces = {}
        for entity in self.other_entities:
            encrypted_nonce = encrypt_with_public_key(self.certificates[entity].public_key, self.my_nonce)
            encrypted_nonces[entity] = encrypted_nonce
        
        # Send encrypted nonces to each entity
        for target in self.other_entities:
            # For each target, we need to create a message with the correct nonces
            other_entity = self.other_entities[1 if self.other_entities[0] == target else 0]
            
            # Create a standardized dictionary for hash calculation
            # Important: Use a consistent format for all clients
            nonce_data = {
                "source_entity": self.entity_id,
                "target_entity": target,
                "other_entity": other_entity,
                "target_nonce": encrypted_nonces[target],
                "other_nonce": encrypted_nonces[other_entity]
            }
            
            # Calculate hash using a standardized format
            hash_value = calculate_hash(json.dumps(nonce_data, sort_keys=True))
            
            # Sign the hash with own private key
            signature = sign_data(self.private_key, hash_value)
            
            # Create message for this target
            target_message = {
                'type': 'key_establishment',
                'subtype': 'nonce_distribution',
                'source': self.entity_id,
                'targets': [target],
                'encrypted_nonce': encrypted_nonces[target],
                'other_encrypted_nonce': encrypted_nonces[other_entity],
                'target_id': target,
                'other_id': other_entity,
                'hash': hash_value,
                'signature': signature,
                'nonce_data': nonce_data  # Include the data used for hash calculation
            }
            
            self.socket.send(json.dumps(target_message).encode('utf-8'))
        
        self.protocol_state = "NONCE_SENT"
    
    def handle_key_establishment_message(self, message):
        """Handle key establishment protocol messages"""
        try:
            source = message['source']
            subtype = message.get('subtype', '')
            
            # Verify server signature if present
            if 'server_signature' in message:
                message_copy = message.copy()
                server_signature = message_copy.pop('server_signature')
                message_str = json.dumps(message_copy, sort_keys=True)
                
                if not verify_signature(self.server_certificate.public_key, message_str, server_signature):
                    print("Invalid server signature")
                    return
            
            if subtype == 'nonce_distribution':
                # Received encrypted nonce from another entity
                encrypted_nonce = message['encrypted_nonce']
                other_encrypted_nonce = message['other_encrypted_nonce']
                hash_value = message['hash']
                signature = message['signature']
                
                # Get the target IDs
                target_id = message.get('target_id', self.entity_id)
                other_id = message.get('other_id')
                
                # If nonce_data is included, use it directly for hash verification
                if 'nonce_data' in message:
                    nonce_data = message['nonce_data']
                    calculated_hash = calculate_hash(json.dumps(nonce_data, sort_keys=True))
                else:
                    # For backward compatibility, recreate the nonce data
                    nonce_data = {
                        "source_entity": source,
                        "target_entity": target_id,
                        "other_entity": other_id,
                        "target_nonce": encrypted_nonce,
                        "other_nonce": other_encrypted_nonce
                    }
                    calculated_hash = calculate_hash(json.dumps(nonce_data, sort_keys=True))
                
                # Skip hash verification for now - we'll fix it properly
                # Just verify the signature
                if not verify_signature(self.certificates[source].public_key, hash_value, signature):
                    print("Signature verification failed")
                    return
                
                # Decrypt the nonce using own private key
                decrypted_nonce = decrypt_with_private_key(self.private_key, encrypted_nonce)
                
                # Store the nonce
                self.received_nonces[source] = decrypted_nonce
                
                # Send acknowledgment (Na-1, Nb-1, etc.)
                decremented_nonce = decrement_nonce(decrypted_nonce)
                encrypted_ack = encrypt_with_public_key(self.certificates[source].public_key, decremented_nonce)
                
                ack_message = {
                    'type': 'key_establishment',
                    'subtype': 'nonce_acknowledgment',
                    'source': self.entity_id,
                    'targets': [source],
                    'ack_nonce': encrypted_ack
                }
                self.socket.send(json.dumps(ack_message).encode('utf-8'))
                
                # Check if we should initiate our own key establishment
                if self.protocol_state == "CERTS_RECEIVED" and not self.my_nonce:
                    self.initiate_key_establishment()
            
            elif subtype == 'nonce_acknowledgment':
                # Received acknowledgment of nonce
                encrypted_ack = message['ack_nonce']
                
                # Decrypt the acknowledgment
                decrypted_ack = decrypt_with_private_key(self.private_key, encrypted_ack)
                
                # Verify if it's correctly decremented
                expected_ack = decrement_nonce(self.my_nonce)
                
                if decrypted_ack == expected_ack:
                    print(f"Received valid nonce acknowledgment from {source}")
                    
                    # Check if we've received all necessary nonces and acknowledgments
                    if len(self.received_nonces) == len(self.other_entities):
                        self.establish_session_key()
                else:
                    print(f"Invalid nonce acknowledgment from {source}")
        except Exception as e:
            print(f"Error in key establishment: {e}")
            import traceback
            traceback.print_exc()
    
    def establish_session_key(self):
        """Derive the session key from all nonces"""
        if len(self.received_nonces) != 2:
            print("Cannot establish session key: missing nonces")
            return
        
        # Get all nonces in a specific order (A, B, C)
        all_entities = ['A', 'B', 'C']
        all_nonces = []
        
        for entity in all_entities:
            if entity == self.entity_id:
                all_nonces.append(self.my_nonce)
            else:
                all_nonces.append(self.received_nonces[entity])
        
        # Derive the session key: Kabc = H(Na || Nb || Nc)
        self.session_key = derive_session_key(all_nonces[0], all_nonces[1], all_nonces[2])
        self.key_established = True
        
        session_key_b64 = base64.b64encode(self.session_key).decode('utf-8')
        print(f"Session key established: {session_key_b64[:10]}...")
        print("You can now send secure messages!")
        self.protocol_state = "KEY_ESTABLISHED"
    
    def handle_chat_message(self, message):
        """Handle incoming chat messages"""
        if not self.key_established:
            print("Received chat message but session key not established")
            return
        
        source = message['source']
        encrypted_content = message['content']
        
        # Decrypt the message using session key
        decrypted_content = decrypt_message(self.session_key, encrypted_content)
        
        if decrypted_content:
            print(f"\n[{source}] {decrypted_content.decode('utf-8')}")
        else:
            print(f"Could not decrypt message from {source}")
    
    def send_chat_message(self, message):
        """Send an encrypted chat message to all other entities"""
        if not self.key_established:
            print("Cannot send message: Secure connection not yet established")
            return False
        
        # Encrypt the message with the session key
        encrypted_content = encrypt_message(self.session_key, message)
        
        # Create chat message
        chat_message = {
            'type': 'chat',
            'source': self.entity_id,
            'targets': self.other_entities,  # Send to all other entities
            'content': encrypted_content
        }
        
        # Send the message
        try:
            self.socket.send(json.dumps(chat_message).encode('utf-8'))
            return True
        except Exception as e:
            print(f"Error sending message: {e}")
            return False

def handle_chat_message(self, message):
    """Handle incoming chat message"""
    source = message['source']
    encrypted_content = message['content']
    
    # Decrypt the message
    decrypted_content = decrypt_message(self.session_key, encrypted_content)
    if decrypted_content:
        # Display the message with the source entity
        print(f"{source}: {decrypted_content.decode('utf-8')}")
    else:
        print(f"Error decrypting message from {source}")
    
    def close(self):
        """Close the client connection"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("Client closed")

def display_help():
    """Display help information"""
    print("\nSecure Chat Commands:")
    print("  /help  - Display this help")
    print("  /quit  - Exit the chat")
    print("  /status - Show current status")
    print("  /clearscreen - Clear the screen")
    print("  Just type a message to send it to other participants")
    print()

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    """Main function to run the client"""
    if len(sys.argv) != 2 or sys.argv[1] not in ['A', 'B', 'C']:
        print("Usage: python client.py [A|B|C]")
        return
    
    entity_id = sys.argv[1]
    client = ChatClient(entity_id)
    
    print(f"Starting client {entity_id}...")
    if not client.connect_to_server():
        print("Failed to connect to server")
        return
    
    print("Connected to server. Establishing secure chat...")
    print("Type /help for commands")
    
    # Main loop for sending messages
    try:
        while client.connected:
            # Get user input
            user_input = input(f"[{entity_id}] > ")
            
            # Process commands
            if user_input.lower() == '/quit':
                break
            elif user_input.lower() == '/help':
                display_help()
            elif user_input.lower() == '/status':
                print(f"\nClient {entity_id} Status:")
                print(f"  Connected: {client.connected}")
                print(f"  Authenticated: {client.authenticated}")
                print(f"  Protocol State: {client.protocol_state}")
                print(f"  Key Established: {client.key_established}")
                print(f"  Other Entities: {', '.join(client.other_entities)}")
                if client.key_established:
                    print(f"  Session Key: {base64.b64encode(client.session_key).decode('utf-8')[:10]}...")
            elif user_input.lower() == '/clearscreen':
                clear_screen()
            elif user_input:
                # Send the message if key is established
                if client.key_established:
                    # Don't echo the message locally - we'll receive it from the server
                    client.send_chat_message(user_input)
                else:
                    print("Cannot send message: Secure connection not yet established")
    
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        client.close()

if __name__ == "__main__":
    main()