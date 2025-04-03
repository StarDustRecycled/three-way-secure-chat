#!/usr/bin/env python3
import os
import json
import asyncio
import logging
import websockets
import argparse
import base64
import crypto_utils
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("client.log"),
        logging.StreamHandler()
    ]
)

class SecureChatClient:
    def __init__(self, client_id, server_url="ws://localhost:8765"):
        self.client_id = client_id
        self.server_url = server_url
        self.logger = logging.getLogger(f"Client_{client_id}")
        
        # Define peer IDs based on client ID
        if client_id == "A":
            self.peers = ["B", "C"]
        elif client_id == "B":
            self.peers = ["A", "C"]
        elif client_id == "C":
            self.peers = ["A", "B"]
        else:
            raise ValueError(f"Invalid client ID: {client_id}")
        
        # Load certificates and keys
        self.certificate = crypto_utils.load_certificate(client_id)
        self.private_key = crypto_utils.load_private_key(client_id)
        self.root_ca_cert = crypto_utils.load_certificate("root_ca")
        
        # Store peer certificates (will be populated during authentication)
        self.peer_certificates = {}
        self.server_certificate = None
        
        # Store nonces during key exchange
        self.local_nonce = None
        self.peer_nonces = {}
        self.shared_key = None
        
        # Keep track of the connection
        self.websocket = None
        self.is_authenticated = False
        self.all_peers_ready = False
        self.incoming_messages = asyncio.Queue()
    
    async def connect_and_authenticate(self):
        """Connect to the server and authenticate"""
        try:
            self.websocket = await websockets.connect(self.server_url)
            self.logger.info(f"Connected to server at {self.server_url}")
            
            # Send authentication request
            auth_request = {
                "client_id": self.client_id,
                "peers": self.peers,
                "certificate": self.certificate
            }
            
            await self.websocket.send(json.dumps(auth_request))
            self.logger.info("Authentication request sent")
            
            # Receive authentication response
            response = await self.websocket.recv()
            response = json.loads(response)
            
            if response["status"] == "authenticated":
                self.peer_certificates = response["peer_certificates"]
                self.server_certificate = self.peer_certificates.get("S")
                
                # Verify peer certificates
                for peer_id, peer_cert in self.peer_certificates.items():
                    if not crypto_utils.verify_certificate(peer_cert, self.root_ca_cert):
                        self.logger.error(f"Certificate verification failed for peer {peer_id}")
                        return False
                # Verify the server certificate
                if not crypto_utils.verify_certificate(self.server_certificate, self.root_ca_cert):
                    self.logger.error("Server certificate verification failed")
                    return False

                # Mark authentication as successful
                self.is_authenticated = True
                self.logger.info("Authentication successful")
                return True
            else:
                self.logger.error(f"Authentication failed: {response['message']}")
                return False
        
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            return False
    
    async def wait_for_all_peers(self):
        """Wait until the server signals that all peers are ready"""
        self.logger.info("Waiting for all peers to be ready...")
        
        while not self.all_peers_ready:
            try:
                raw_message = await self.websocket.recv()
                message = json.loads(raw_message)
                
                if message.get("type") == "all_peers_ready":
                    self.all_peers_ready = True
                    self.logger.info("All peers are ready to begin key exchange")
                    return True
                else:
                    # Store other messages for later processing
                    await self.incoming_messages.put(message)
            
            except Exception as e:
                self.logger.error(f"Error waiting for peers: {e}")
                return False
        
        return True
    
    async def key_exchange_phase(self):
        """Execute the key exchange protocol"""
        if not self.is_authenticated:
            self.logger.error("Cannot perform key exchange without authentication")
            return False
        
        # # Wait until all peers are ready before starting key exchange
        # if not await self.wait_for_all_peers():
        #     return False
        
        if self.client_id == "A":
            return await self.key_exchange_A()
        elif self.client_id == "B":
            return await self.key_exchange_B()
        elif self.client_id == "C":
            return await self.key_exchange_C()
    
    async def key_exchange_A(self):
        """Key exchange protocol for client A"""
        self.logger.info("Starting key exchange as client A")
        
        try:
            # Generate nonce Na
            self.local_nonce = crypto_utils.generate_nonce()
            self.logger.info("Generated nonce Na")
            
            # Encrypt Na for B and C
            message_to_B = crypto_utils.prepare_nonce_message(
                self.local_nonce, "B", self.client_id
            )
            
            message_to_C = crypto_utils.prepare_nonce_message(
                self.local_nonce, "C", self.client_id
            )
            
            # Send encrypted nonces to server for relay
            for msg, recipient in [(message_to_B, "B"), (message_to_C, "C")]:
                await self.websocket.send(json.dumps({
                    "type": "nonce_message",
                    "data": msg
                }))
                
                # Wait for server acknowledgment
                response = await self.websocket.recv()
                response = json.loads(response)
                
                if response["status"] != "relayed":
                    self.logger.error(f"Failed to relay nonce to {recipient}: {response.get('message')}")
                    return False
            
            self.logger.info("Sent Na to B and C")
            
            # Receive Nb from B (and Na-1)
            _, nonce_B = await self.receive_nonce("B")
            
            # Verify that B sent back Na-1
            expected_na_minus_1 = crypto_utils.increment_nonce(self.local_nonce)
            if nonce_B[len(nonce_B) - len(expected_na_minus_1):] != expected_na_minus_1:
                self.logger.error("Challenge response from B verification failed")
                return False
            
            # Extract Nb from B's message
            nb = nonce_B[:len(nonce_B) - len(expected_na_minus_1)]
            self.peer_nonces["B"] = nb
            self.logger.info("Received valid Nb from B")
            
            # Receive Nc from C
            _, nonce_C = await self.receive_nonce("C")
            self.peer_nonces["C"] = nonce_C
            self.logger.info("Received Nc from C")
            
            # Send Nb-1 to B and Nc-1 to C
            nb_minus_1 = crypto_utils.increment_nonce(nb)
            nc_minus_1 = crypto_utils.increment_nonce(nonce_C)
            
            message_to_B = crypto_utils.prepare_nonce_message(
                nb_minus_1, "B", self.client_id
            )
            
            message_to_C = crypto_utils.prepare_nonce_message(
                nc_minus_1, "C", self.client_id
            )
            
            for msg, recipient in [(message_to_B, "B"), (message_to_C, "C")]:
                await self.websocket.send(json.dumps({
                    "type": "nonce_message",
                    "data": msg
                }))
                
                # Wait for server acknowledgment
                response = await self.websocket.recv()
                response = json.loads(response)
                
                if response["status"] != "relayed":
                    self.logger.error(f"Failed to relay challenge response to {recipient}")
                    return False
            
            self.logger.info("Sent challenge responses to B and C")
            
            # Compute the shared key
            self.derive_shared_key()
            return True
        
        except Exception as e:
            self.logger.error(f"Key exchange error: {e}")
            return False
    
    async def key_exchange_B(self):
        """Key exchange protocol for client B"""
        self.logger.info("Starting key exchange as client B")
        
        try:
            # Receive Na from A
            _, nonce_A = await self.receive_nonce("A")
            self.peer_nonces["A"] = nonce_A
            self.logger.info("Received Na from A")
            
            # Generate nonce Nb
            self.local_nonce = crypto_utils.generate_nonce()
            self.logger.info("Generated nonce Nb")
            
            # Create Na-1 as challenge response
            na_minus_1 = crypto_utils.increment_nonce(nonce_A)
            
            # Combine Nb and Na-1 for A
            combined_nonce = self.local_nonce + na_minus_1
            
            # Encrypt and send Nb,Na-1 to A and Nb to C
            message_to_A = crypto_utils.prepare_nonce_message(
                combined_nonce, "A", self.client_id
            )
            
            message_to_C = crypto_utils.prepare_nonce_message(
                self.local_nonce, "C", self.client_id
            )
            
            for msg, recipient in [(message_to_A, "A"), (message_to_C, "C")]:
                await self.websocket.send(json.dumps({
                    "type": "nonce_message",
                    "data": msg
                }))
                
                # Wait for server acknowledgment
                response = await self.websocket.recv()
                response = json.loads(response)
                
                if response["status"] != "relayed":
                    self.logger.error(f"Failed to relay nonce to {recipient}")
                    return False
            
            self.logger.info("Sent Nb,Na-1 to A and Nb to C")
            
            # Receive Nc from C
            _, nonce_C = await self.receive_nonce("C")
            self.peer_nonces["C"] = nonce_C
            self.logger.info("Received Nc from C")
            
            # Receive Nb-1 from A
            _, nb_minus_1 = await self.receive_nonce("A")
            
            # Verify Nb-1
            expected_nb_minus_1 = crypto_utils.increment_nonce(self.local_nonce)
            if nb_minus_1 != expected_nb_minus_1:
                self.logger.error("Challenge response from A verification failed")
                return False
            
            self.logger.info("Verified challenge response from A")
            
            # Send Nc-1 to C
            nc_minus_1 = crypto_utils.increment_nonce(nonce_C)
            message_to_C = crypto_utils.prepare_nonce_message(
                nc_minus_1, "C", self.client_id
            )
            
            await self.websocket.send(json.dumps({
                "type": "nonce_message",
                "data": message_to_C
            }))
            
            # Wait for server acknowledgment
            response = await self.websocket.recv()
            response = json.loads(response)
            
            if response["status"] != "relayed":
                self.logger.error("Failed to relay challenge response to C")
                return False
            
            self.logger.info("Sent challenge response to C")
            
            # Compute the shared key
            self.derive_shared_key()
            return True
        
        except Exception as e:
            self.logger.error(f"Key exchange error: {e}")
            return False
    
    async def key_exchange_C(self):
        """Key exchange protocol for client C"""
        self.logger.info("Starting key exchange as client C")
        
        try:
            # Receive Na from A and Nb from B
            _, nonce_A = await self.receive_nonce("A")
            self.peer_nonces["A"] = nonce_A
            self.logger.info("Received Na from A")
            
            _, nonce_B = await self.receive_nonce("B")
            self.peer_nonces["B"] = nonce_B
            self.logger.info("Received Nb from B")
            
            # Generate nonce Nc
            self.local_nonce = crypto_utils.generate_nonce()
            self.logger.info("Generated nonce Nc")
            
            # Create challenge responses
            na_minus_1 = crypto_utils.increment_nonce(nonce_A)
            nb_minus_1 = crypto_utils.increment_nonce(nonce_B)
            
            # Send Nc to A and B
            message_to_A = crypto_utils.prepare_nonce_message(
                self.local_nonce, "A", self.client_id
            )
            
            message_to_B = crypto_utils.prepare_nonce_message(
                self.local_nonce, "B", self.client_id
            )
            
            for msg, recipient in [(message_to_A, "A"), (message_to_B, "B")]:
                await self.websocket.send(json.dumps({
                    "type": "nonce_message",
                    "data": msg
                }))
                
                # Wait for server acknowledgment
                response = await self.websocket.recv()
                response = json.loads(response)
                
                if response["status"] != "relayed":
                    self.logger.error(f"Failed to relay nonce to {recipient}")
                    return False
            
            self.logger.info("Sent Nc to A and B")
            
            # Receive Nc-1 from A
            _, nc_minus_1_from_A = await self.receive_nonce("A")
            
            # Verify Nc-1 from A
            expected_nc_minus_1 = crypto_utils.increment_nonce(self.local_nonce)
            if nc_minus_1_from_A != expected_nc_minus_1:
                self.logger.error("Challenge response from A verification failed")
                return False
            
            self.logger.info("Verified challenge response from A")
            
            # Receive Nc-1 from B
            _, nc_minus_1_from_B = await self.receive_nonce("B")
            
            # Verify Nc-1 from B
            if nc_minus_1_from_B != expected_nc_minus_1:
                self.logger.error("Challenge response from B verification failed")
                return False
            
            self.logger.info("Verified challenge response from B")
            
            # Compute the shared key
            self.derive_shared_key()
            return True
        
        except Exception as e:
            self.logger.error(f"Key exchange error: {e}")
            return False
    
    async def receive_nonce(self, sender_id):
        """Receive and verify a nonce message from a specific sender"""
        while True:
            # Check if we have any messages in the queue first
            if not self.incoming_messages.empty():
                message = await self.incoming_messages.get()
            else:
                # Receive message from the server
                raw_message = await self.websocket.recv()
                message = json.loads(raw_message)
            
            if message.get("type") == "nonce_message":
                nonce_message = message["data"]
                
                if nonce_message["sender"] == sender_id and nonce_message["recipient"] == self.client_id:
                    # Verify the message using server's certificate
                    verified, nonce = crypto_utils.verify_nonce_message(nonce_message, self.server_certificate)
                    
                    if verified:
                        self.logger.info(f"Received verified nonce from {sender_id}")
                        return True, nonce
                    else:
                        self.logger.error(f"Failed to verify nonce from {sender_id}")
                        return False, None
            
            # If the message is not what we're looking for, put it back in the queue for later
            await self.incoming_messages.put(message)
    
    def derive_shared_key(self):
        """Derive the shared key from all nonces"""
        if self.client_id == "A":
            self.shared_key = crypto_utils.derive_shared_key(
                self.local_nonce, self.peer_nonces["B"], self.peer_nonces["C"]
            )
        elif self.client_id == "B":
            self.shared_key = crypto_utils.derive_shared_key(
                self.peer_nonces["A"], self.local_nonce, self.peer_nonces["C"]
            )
        elif self.client_id == "C":
            self.shared_key = crypto_utils.derive_shared_key(
                self.peer_nonces["A"], self.peer_nonces["B"], self.local_nonce
            )
        
        # Save the shared key
        crypto_utils.save_shared_key(self.shared_key)
        self.logger.info("Derived and saved shared key successfully")
    
    async def send_message(self, message, recipients=None):
        """Send an encrypted message to other clients"""
        if not self.shared_key:
            self.logger.error("Cannot send message without shared key")
            return False
        
        if recipients is None:
            recipients = self.peers
        
        message_data = {
            "text": message,
            "sender": self.client_id,
            "timestamp": str(asyncio.get_event_loop().time())
        }
        
        # Encrypt the message with the shared key
        encrypted_data = crypto_utils.encrypt_message(json.dumps(message_data), self.shared_key)
        
        # Send the encrypted message to each recipient
        for recipient in recipients:
            chat_message = {
                "sender": self.client_id,
                "recipient": recipient,
                "encrypted_data": encrypted_data
            }
            
            await self.websocket.send(json.dumps({
                "type": "chat_message",
                "data": chat_message
            }))
            
            # Don't wait for acknowledgment here - it will be handled by receive_messages()
        
        return True
    
    async def receive_messages(self):
        """Receive and decrypt messages from other clients"""
        while True:
            try:
                # Check if we have any messages in the queue first
                if not self.incoming_messages.empty():
                    message = await self.incoming_messages.get()
                else:
                    # Wait for new messages
                    raw_message = await self.websocket.recv()
                    message = json.loads(raw_message)
                
                if message.get("type") == "chat_message":
                    chat_message = message["data"]
                    sender = chat_message.get("sender")
                    
                    # Check if signature is present and server certificate is available
                    if "server_signature" in chat_message and self.server_certificate is not None:
                        # Verify server signature
                        server_signature = base64.b64decode(chat_message["server_signature"])
                        
                        if not crypto_utils.verify_signature(
                            json.dumps(chat_message["encrypted_data"]).encode('utf-8'),
                            server_signature,
                            self.server_certificate["public_key"]
                        ):
                            self.logger.error(f"Server signature verification failed for message from {sender}")
                            continue
                    else:
                        self.logger.warning(f"Missing signature or server certificate for message from {sender}")
                    
                    # Decrypt the message
                    try:
                        decrypted_text = crypto_utils.decrypt_message(
                            chat_message["encrypted_data"], self.shared_key
                        )
                        decrypted_data = json.loads(decrypted_text)
                        
                        # Display the message
                        print(f"\nFrom {sender}: {decrypted_data['text']}")
                        
                    except Exception as e:
                        self.logger.error(f"Failed to decrypt message from {sender}: {e}")
                
            except websockets.exceptions.ConnectionClosed:
                self.logger.error("Connection to server closed")
                break
            
            except Exception as e:
                self.logger.error(f"Error receiving messages: {e}")

    async def wait_for_peers_ready(self):
        """Wait for notification that all peers are ready"""
        while True:
            raw_message = await self.websocket.recv()
            message = json.loads(raw_message)
        
            if message.get("type") == "all_peers_ready":
                self.logger.info("All peers are ready, starting key exchange...")
                return
        
            # If it's not the ready message, put it in the queue for later processing
            await self.incoming_messages.put(message)

    async def start(self):
        """Start the client"""
        # Connect and authenticate
        if not await self.connect_and_authenticate():
            return False
        
        # Wait for server to confirm all peers are ready
        self.logger.info("Waiting for all peers to be ready...")
        await self.wait_for_peers_ready()  # 


        # Perform key exchange
        if not await self.key_exchange_phase():
            return False
        
        # Start receiving messages in the background
        asyncio.create_task(self.receive_messages())
        
        # Chat loop
        while True:
            try:
                # Get user input for sending messages
                message = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: input(f"\n{self.client_id}> ")
                )
                
                if message.lower() in ['exit', 'quit']:
                    break
                
                # Send the message
                await self.send_message(message)
                
            except KeyboardInterrupt:
                break
            
            except Exception as e:
                self.logger.error(f"Error in chat loop: {e}")
        
        # Close the connection
        if self.websocket:
            await self.websocket.close()

async def main():
    parser = argparse.ArgumentParser(description="Secure Three-Way Chat Client")
    parser.add_argument("client_id", choices=["A", "B", "C"], help="Client identifier (A, B, or C)")
    parser.add_argument("--server", default="ws://localhost:8765", help="WebSocket server URL")
    args = parser.parse_args()
    
    
    # Create and start the client
    client = SecureChatClient(args.client_id, args.server)
    await client.start()

if __name__ == "__main__":
    asyncio.run(main())