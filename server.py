import socket
import threading
import json
import base64
import sys
import time
from crypto_utils import Certificate, generate_key_pair, verify_signature, sign_data, save_key_pair

class ChatServer:
    def __init__(self, host='127.0.0.1', port=5000):
        """Initialize the chat server"""
        # Generate server key pair
        self.private_key, self.public_key = generate_key_pair()
        save_key_pair(self.private_key, "S")
        self.certificate = Certificate("S", self.public_key)
        
        # Set up server socket
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        
        # Store client connections and certificates
        self.clients = {}  # entity_id -> socket
        self.certificates = {}  # entity_id -> Certificate
        
        # Add server's own certificate
        self.certificates["S"] = self.certificate
        
        # Thread lock for thread safety
        self.lock = threading.Lock()
        
        # Keep track of pending certificate requests
        self.pending_cert_requests = {}  # entity_id -> list of entities waiting for this certificate
        
        print(f"Chat Server initialized on {host}:{port}")
    
    def start(self):
        """Start the server and listen for connections"""
        self.server_socket.listen(5)
        print("Server is listening for connections...")
        
        try:
            while True:
                client_socket, address = self.server_socket.accept()
                
                # Start a new thread to handle this client
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            print("Server shutting down...")
        finally:
            self.server_socket.close()
    
    def handle_client(self, client_socket):
        """Handle client connection and process messages"""
        entity_id = None
        
        try:
            while True:
                # Receive data from client
                data = client_socket.recv(4096)
                if not data:
                    break
                
                # Parse the message
                message = json.loads(data.decode('utf-8'))
                message_type = message.get('type')
                
                # Process different message types
                if message_type == 'register':
                    # Handle registration message
                    entity_id = message['entity_id']
                    cert_data = message['certificate']
                    certificate = Certificate.deserialize(cert_data)
                    
                    with self.lock:
                        self.certificates[entity_id] = certificate
                        self.clients[entity_id] = client_socket
                    
                    print(f"Entity {entity_id} connected")
                    
                    # Send server certificate and acknowledgment
                    response = {
                        'type': 'register_ack',
                        'server_cert': self.certificate.serialize()
                    }
                    client_socket.send(json.dumps(response).encode('utf-8'))
                    
                    # Check if any clients are waiting for this certificate
                    if entity_id in self.pending_cert_requests:
                        for waiting_entity in self.pending_cert_requests[entity_id]:
                            if waiting_entity in self.clients:
                                # Send the new certificate to waiting clients
                                cert_response = {
                                    'type': 'certificate_response',
                                    'certificates': {entity_id: certificate.serialize()}
                                }
                                try:
                                    self.clients[waiting_entity].send(json.dumps(cert_response).encode('utf-8'))
                                except Exception:
                                    pass
                        # Clear the pending requests
                        del self.pending_cert_requests[entity_id]
                
                elif message_type == 'certificate_request':
                    # Handle certificate request
                    if not entity_id:
                        continue
                    
                    requested_entities = message['entities']
                    certificates = {}
                    missing_entities = []
                    
                    for req_entity in requested_entities:
                        if req_entity in self.certificates:
                            certificates[req_entity] = self.certificates[req_entity].serialize()
                        else:
                            missing_entities.append(req_entity)
                            # Add this client to pending requests for the missing certificate
                            if req_entity not in self.pending_cert_requests:
                                self.pending_cert_requests[req_entity] = []
                            self.pending_cert_requests[req_entity].append(entity_id)
                    
                    # Send available certificates immediately
                    if certificates:
                        response = {
                            'type': 'certificate_response',
                            'certificates': certificates
                        }
                        client_socket.send(json.dumps(response).encode('utf-8'))
                
                elif message_type == 'key_establishment':
                    # Handle key establishment messages
                    if not entity_id:
                        continue
                    
                    # Extract message details
                    source = message['source']
                    targets = message['targets']
                    
                    # Sign the message using server's private key to prove it came from the server
                    message['server_signature'] = sign_data(self.private_key, json.dumps(message, sort_keys=True))
                    
                    # Forward the message to all targets
                    for target in targets:
                        if target in self.clients:
                            try:
                                self.clients[target].send(json.dumps(message).encode('utf-8'))
                            except Exception:
                                pass
                
                elif message_type == 'chat':
                    # Handle encrypted chat messages
                    if not entity_id:
                        continue
                    
                    source = message['source']
                    targets = message['targets']
                    
                    # Forward the message to all targets
                    for target in targets:
                        if target in self.clients:
                            try:
                                self.clients[target].send(json.dumps(message).encode('utf-8'))
                            except Exception:
                                pass
        
        except Exception as e:
            print(f"Error handling client: {e}")
        
        finally:
            # Clean up when client disconnects
            if entity_id and entity_id in self.clients:
                with self.lock:
                    del self.clients[entity_id]
                    print(f"Entity {entity_id} disconnected")
            
            client_socket.close()

    def stop(self):
        """Gracefully stop the server"""
        self.running = False
        print("\nShutting down server...")
        self.server_socket.close()

if __name__ == "__main__":
    # Create and start the server
    server = ChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()