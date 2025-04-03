#!/usr/bin/env python3
import asyncio
import json
import logging
import websockets
import crypto_utils
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Server")

# Global state for connected clients
CLIENTS = {}
CERTIFICATES = {}
ROOT_CA_CERT = None
EXPECTED_CLIENTS = ["A", "B", "C"]  # Expected client IDs

async def handle_authentication(websocket, path):
    """Handle the authentication phase of the protocol"""
    try:
        # Receive authentication request
        auth_data = await websocket.recv()
        auth_data = json.loads(auth_data)
        
        client_id = auth_data["client_id"]
        requested_peers = auth_data["peers"]
        client_cert = auth_data["certificate"]
        
        logger.info(f"Authentication request from {client_id}")
        
        # Verify client certificate against root CA
        if not crypto_utils.verify_certificate(client_cert, ROOT_CA_CERT):
            await websocket.send(json.dumps({
                "status": "error",
                "message": "Certificate verification failed"
            }))
            return None
        
        # Store client certificate
        CERTIFICATES[client_id] = client_cert
        
        # Send peer certificates to client
        peer_certs = {}
        for peer_id in requested_peers:
            # Load peer certificate if not already loaded
            if peer_id not in CERTIFICATES:
                try:
                    peer_cert = crypto_utils.load_certificate(peer_id)
                    CERTIFICATES[peer_id] = peer_cert
                except FileNotFoundError:
                    await websocket.send(json.dumps({
                        "status": "error",
                        "message": f"Certificate for peer {peer_id} not found"
                    }))
                    return None
            
            peer_certs[peer_id] = CERTIFICATES[peer_id]
            
        # Always include the server certificate
        peer_certs["S"] = CERTIFICATES["S"]
        
        # Send the peer certificates to the client
        await websocket.send(json.dumps({
            "status": "authenticated",
            "peer_certificates": peer_certs
        }))
        
        # Store the websocket connection
        CLIENTS[client_id] = websocket
        
        # Check if all expected clients are connected and notify them
        await check_all_clients_ready()
        
        return client_id
    
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        await websocket.send(json.dumps({
            "status": "error",
            "message": f"Authentication error: {str(e)}"
        }))
        return None

async def check_all_clients_ready():
    """Check if all expected clients are connected and notify them if so"""
    if all(client_id in CLIENTS for client_id in EXPECTED_CLIENTS):
        logger.info("All expected clients are connected! Notifying clients to start key exchange.")
        
        # Notify all clients that all peers are ready
        for client_id, websocket in CLIENTS.items():
            if client_id in EXPECTED_CLIENTS:
                try:
                    await websocket.send(json.dumps({
                        "type": "all_peers_ready",
                        "message": "All peers are connected and ready for key exchange"
                    }))
                    logger.info(f"Sent ready notification to client {client_id}")
                except Exception as e:
                    logger.error(f"Error sending ready notification to client {client_id}: {e}")

async def relay_message(message, server_cert):
    """Relay a message to its intended recipient with server signature"""
    try:
        # Extract message details
        sender = message["sender"]
        recipient = message["recipient"]
        
        # Sign the message as server
        signed_message = crypto_utils.sign_server_message(message)
        
        # Relay the message if recipient is connected
        if recipient in CLIENTS:
            await CLIENTS[recipient].send(json.dumps({
                "type": "nonce_message",
                "data": signed_message
            }))
            logger.info(f"Relayed message from {sender} to {recipient}")
            return True
        else:
            logger.warning(f"Recipient {recipient} not connected")
            return False
    
    except Exception as e:
        logger.error(f"Error relaying message: {e}")
        return False

async def handle_client(websocket, path):
    """Handle a client connection"""
    client_id = None
    
    try:
        # Handle authentication phase
        client_id = await handle_authentication(websocket, path)
        if not client_id:
            return
        
        logger.info(f"Client {client_id} authenticated successfully")
        
        # Main message handling loop
        async for message in websocket:
            try:
                data = json.loads(message)
                message_type = data.get("type")
                
                if message_type == "nonce_message":
                    # Handle nonce messages during key exchange
                    nonce_message = data["data"]
                    success = await relay_message(nonce_message, CERTIFICATES["S"])
                    
                    if success:
                        # Send acknowledgment back to sender
                        await websocket.send(json.dumps({
                            "status": "relayed",
                            "recipient": nonce_message["recipient"]
                        }))
                    else:
                        await websocket.send(json.dumps({
                            "status": "error",
                            "message": f"Failed to relay message to {nonce_message['recipient']}"
                        }))
                
                elif message_type == "chat_message":
                    # Handle encrypted chat messages
                    # The server just relays these without decrypting
                    chat_message = data["data"]
                    recipient = chat_message["recipient"]
                    
                    if recipient in CLIENTS:
                        # Sign the encrypted message
                        server_signature = crypto_utils.sign_data(
                            json.dumps(chat_message["encrypted_data"]).encode('utf-8'),
                            crypto_utils.load_private_key("S")
                        )
                        
                        chat_message["server_signature"] = crypto_utils.base64.b64encode(server_signature).decode('utf-8')
                        
                        # Relay the message
                        await CLIENTS[recipient].send(json.dumps({
                            "type": "chat_message",
                            "data": chat_message
                        }))
                        
                        # Send acknowledgment
                        await websocket.send(json.dumps({
                            "status": "relayed",
                            "recipient": recipient
                        }))
                    else:
                        await websocket.send(json.dumps({
                            "status": "error",
                            "message": f"Recipient {recipient} not connected"
                        }))
                
                elif message_type == "request_server_certificate":
                    # Send server certificate to client
                    await websocket.send(json.dumps({
                        "type": "server_certificate",
                        "certificate": CERTIFICATES["S"]
                    }))
                    logger.info(f"Sent server certificate to client {client_id}")
                
                else:
                    logger.warning(f"Unknown message type: {message_type}")
                    await websocket.send(json.dumps({
                        "status": "error",
                        "message": f"Unknown message type: {message_type}"
                    }))
            
            except json.JSONDecodeError:
                logger.error("Received invalid JSON")
                await websocket.send(json.dumps({
                    "status": "error",
                    "message": "Invalid JSON format"
                }))
            
            except Exception as e:
                logger.error(f"Error processing message: {e}")
                await websocket.send(json.dumps({
                    "status": "error",
                    "message": f"Error processing message: {str(e)}"
                }))
    
    except websockets.exceptions.ConnectionClosed:
        logger.info(f"Connection closed for client {client_id}")
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    
    finally:
        # Clean up when a client disconnects
        if client_id and client_id in CLIENTS:
            del CLIENTS[client_id]
            logger.info(f"Client {client_id} disconnected")

async def main():
    # Load server certificate and root CA certificate
    global ROOT_CA_CERT
    
    try:
        server_cert = crypto_utils.load_certificate("S")
        ROOT_CA_CERT = crypto_utils.load_certificate("root_ca")
        
        # Verify server certificate against root CA
        if not crypto_utils.verify_certificate(server_cert, ROOT_CA_CERT):
            logger.error("Server certificate verification failed")
            return
        
        # Store server certificate
        CERTIFICATES["S"] = server_cert
        
        # Start the server
        port = 8765
        server = await websockets.serve(handle_client, "localhost", port)
        
        logger.info(f"Server started on port {port}")
        
        # Keep the server running
        await server.wait_closed()
    
    except FileNotFoundError as e:
        logger.error(f"Certificate file not found: {e}")
        logger.error("Make sure to run setup.py first to generate certificates")
    
    except Exception as e:
        logger.error(f"Server initialization error: {e}")

if __name__ == "__main__":
    asyncio.run(main())