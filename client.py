import socket
import threading

class ChatClient:
    def __init__(self, host='127.0.0.1', port=5555):
        self.nickname = input("Choose your nickname: ")
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((host, port))
        
        # Send nickname to server
        self.client.send(self.nickname.encode('utf-8'))
        
        # Start separate threads for sending and receiving messages
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.daemon = True
        receive_thread.start()
        
        send_thread = threading.Thread(target=self.send_messages)
        send_thread.daemon = True
        send_thread.start()
        
        # Keep the main thread alive
        try:
            send_thread.join()
        except KeyboardInterrupt:
            print("\nDisconnecting from chat...")
            self.client.close()
    
    def receive_messages(self):
        while True:
            try:
                message = self.client.recv(1024).decode('utf-8')
                if not message:
                    print("Connection closed by server")
                    self.client.close()
                    break
                print(message)
            except ConnectionResetError:
                print("Connection was forcibly closed by the server")
                self.client.close()
                break
            except Exception as e:
                print(f"Error receiving message: {str(e)}")
                self.client.close()
                break
    
    def send_messages(self):
        while True:
            try:
                message = input()
                if message.lower() == 'quit':
                    self.client.close()
                    break
                self.client.send(message.encode('utf-8'))
            except:
                print("Error sending message")
                self.client.close()
                break

if __name__ == "__main__":
    client = ChatClient()