import sqlite3
import socket
import threading
from protocol import SecureChatProtocol

class ChatServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clients = []
        self.protocol = SecureChatProtocol()
        self.init_db()

    def init_db(self):
        self.conn = sqlite3.connect('chat.db')
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()

    def broadcast(self, message, exclude_client=None):
        for client in self.clients:
            if client != exclude_client:
                client.send(message)

    def handle_client(self, client_socket):
        while True:
            try:
                encrypted_message = client_socket.recv(1024)
                message = self.protocol.decrypt_message(encrypted_message)
                self.cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
                self.conn.commit()
                self.broadcast(encrypted_message, exclude_client=client_socket)
            except Exception as e:
                print(f"Error: {e}")
                self.clients.remove(client_socket)
                client_socket.close()
                break

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")

        while True:
            client_socket, addr = server_socket.accept()
            self.clients.append(client_socket)
            print(f"New connection from {addr}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    server = ChatServer('0.0.0.0', 5222)
    server.start()
