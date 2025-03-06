import socket
import threading

class ChatServer:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}
        self.nicknames = {}

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(3)  # Listen for 3 clients
        print(f"Server started on {self.host}:{self.port}")

        while True:
            try:
                client_socket, address = self.server_socket.accept()
                if len(self.clients) >= 3:
                    client_socket.send("Chat room is full. Please try again later.".encode('utf-8'))
                    client_socket.close()
                    continue

                print(f"Connected with {str(address)}")

                # Receive nickname
                nickname = client_socket.recv(1024).decode('utf-8')
                self.nicknames[client_socket] = nickname
                self.clients[client_socket] = address

                # Start handling thread for this client
                thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                thread.daemon = True
                thread.start()

                # Broadcast connection message
                self.broadcast(f"{nickname} joined the chat!", client_socket)
            except Exception as e:
                print(f"Error accepting connection: {str(e)}")
                continue

    def handle_client(self, client_socket):
        while True:
            try:
                message = client_socket.recv(1024).decode('utf-8')
                if message:
                    # Broadcast the message to all other clients
                    self.broadcast(f"{self.nicknames[client_socket]}: {message}", client_socket)
                else:
                    self.remove_client(client_socket)
                    break
            except:
                self.remove_client(client_socket)
                break

    def broadcast(self, message, sender_socket):
        for client in self.clients:
            if client != sender_socket:  # Don't send back to sender
                try:
                    client.send(message.encode('utf-8'))
                except:
                    self.remove_client(client)

    def remove_client(self, client_socket):
        if client_socket in self.clients:
            nickname = self.nicknames[client_socket]
            print(f"{nickname} left the chat")
            self.broadcast(f"{nickname} left the chat!", client_socket)
            del self.nicknames[client_socket]
            del self.clients[client_socket]
            client_socket.close()

if __name__ == "__main__":
    server = ChatServer()
    server.start()