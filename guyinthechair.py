
# Server

print("hello there, fool!")

import socket

HOST = 'localhost'
PORT = 45678

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()  # Sets the server to listen for incoming requests

    while True:
        print("\nListening for incoming connections")
        conn, addr = s.accept()  # Block here until request received
        # Accepts creates a new socket object that we'll be using to
        # communicate with the client.
        # It's different from the socket the server is using to listen
        # for new connections, as we can see with the different port.

        with conn:
            print("Connection from", addr)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                print(data.decode('utf-8'))
