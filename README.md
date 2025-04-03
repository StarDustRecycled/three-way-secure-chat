# Secure Three-Way Chat System

This is a fully functional Python implementation of a secure three-way chat system that supports encrypted communications among clients A, B, and C while ensuring that the central server (S) only relays and signs messages without reading their contents.

## Features

- **Certificate Management**: Root CA generates signed certificates for all entities (A, B, C, S)
- **Secure Authentication**: Entities verify each other's identities via certificates
- **RSA Key Exchange**: Secure exchange of nonces between clients
- **AES-GCM Encryption**: End-to-end encrypted chat messages
- **Digital Signatures**: Message integrity protection
- **Asynchronous Communication**: Using asyncio and WebSockets

## Project Structure

```
.
├── setup.py                  # Setup script for certificates and keys
├── server.py                 # Server implementation
├── client.py                 # Client implementation for A, B, and C
├── crypto_utils.py           # Cryptographic utility functions
└── certs/                    # Generated certificates and keys
    ├── root_ca_cert.json     # Root CA certificate
    ├── root_ca_private.pem   # Root CA private key
    ├── a_cert.json           # Client A certificate
    ├── a_private.pem         # Client A private key
    ├── b_cert.json           # Client B certificate
    ├── b_private.pem         # Client B private key
    ├── c_cert.json           # Client C certificate
    ├── c_private.pem         # Client C private key
    ├── s_cert.json           # Server certificate
    ├── s_private.pem         # Server private key
    └── shared_key.json       # Shared AES key (populated after key exchange)
```

## Prerequisites

- Python 3.7+
- PyCryptodome
- websockets

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/secure-three-way-chat.git
   cd secure-three-way-chat
   ```

2. Create a virtual environment and install dependencies:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install pycryptodome websockets
   ```

## Usage

1. Run the setup script to generate certificates:
   ```
   python setup.py
   ```

2. Start the server:
   ```
   python server.py
   ```

3. In separate terminals, start the clients:
   ```
   python client.py A
   python client.py B
   python client.py C
   ```

4. Type messages in any client terminal to send to the other clients. All messages will be encrypted end-to-end.

## Protocol Description

### Authentication Phase

1. Each client (A, B, C) sends its certificate to the server (S)
2. Server sends peer certificates to each client
3. All entities verify certificates using the root CA

### Key Exchange Phase

The protocol follows these steps:

1. Client A generates nonce Na and sends it to B and C
2. Client B generates nonce Nb, responds with (Nb, Na-1) to A, and Nb to C
3. Client C generates nonce Nc and sends it to A and B
4. Clients verify the challenge responses (incremented nonces)
5. The shared key is derived: K_abc = H(Na || Nb || Nc)

### Secure Communication

- Messages are encrypted using AES-GCM with the shared key
- Server signs but doesn't decrypt messages
- Digital signatures ensure message integrity

## Security Features

- **Certificate Authority**: All certificates are signed by a root CA
- **Mutual Authentication**: All entities authenticate each other
- **Challenge-Response**: Nonce incrementation for freshness verification
- **End-to-end Encryption**: Server cannot read message contents
- **Message Integrity**: Digital signatures prevent tampering

## Development

This implementation follows a modular approach:
- `setup.py`: Certificate generation and initialization
- `crypto_utils.py`: Cryptographic operations
- `server.py`: WebSocket server and message relay
- `client.py`: Client implementation for end users

The code is extensively documented with inline comments explaining both the cryptographic operations and the asynchronous communication flow.