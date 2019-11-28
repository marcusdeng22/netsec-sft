
# Server

import socket
import random

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from crypto import genOTP, XOR_bytes
from utils import recv_file, send_file

def main():
    HOST = 'localhost'
    PORT = 45678
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()  # Sets the server to listen for incoming requests

        print("Listening for incoming connections\n")
        conn, addr = s.accept()  # Block here until request received
        # Accepts creates a new socket object that we'll be using to
        # communicate with the client.
        # It's different from the socket the server is using to listen
        # for new connections, as we can see with the different port.

        with conn:
            BLOCK_SIZE_BYTES = 16

            # Authenticate self to client: open private key to decrypt message: secret key concatenated with IV
            SECRET_KEY, IV = get_secrets(conn, BLOCK_SIZE_BYTES)

            # send back verification: SECRET_KEY XOR IV
            verification = XOR_bytes(SECRET_KEY, IV)
            conn.sendall(verification)

            temp_mode = conn.recv(4)
            # if no data then our authentication was bad and the client closed the connection
            if not temp_mode:
                print("Authentication failure")
                return

            # Guarantee we read 4 bytes of mode from client
            if len(temp_mode) < 4:
                leftover = 4 - len(temp_mode)
                temp_mode += read_bytes(conn, leftover)

            # read the file name from client
            tempFile = conn.recv(1024).decode("utf-8")
            MODE = temp_mode.decode('utf=8').strip()
            FILE = tempFile.strip()

            print("mode:", MODE)
            print("file:", FILE)

            if MODE == "up":
                FILE = FILE.split('.')    # For testing
                FILE = FILE[0] + "_testing." + FILE[1]
                if not recv_file(FILE, SECRET_KEY, IV, BLOCK_SIZE_BYTES, conn):
                    print("failed to save file")
                else:
                    print("file saved!")
            elif MODE == "down":
                if not send_file(FILE, SECRET_KEY, IV, BLOCK_SIZE_BYTES, conn):
                    print("failed to read file")
                else:
                    print("file sent")
            print("done")


def get_secrets(conn, BLOCK_SIZE_BYTES):
    with open("private_key.pem", "rb") as key_file:
        PRIVATE_KEY = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        enc_auth_token = conn.recv(256)  # encrypted auth token is 256 bytes
        auth_token = PRIVATE_KEY.decrypt(
            enc_auth_token,
            padding.OAEP(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Parse secret key and IV from the received message.
        SECRET_KEY = auth_token[:BLOCK_SIZE_BYTES]
        IV = auth_token[BLOCK_SIZE_BYTES:]

        return SECRET_KEY, IV


def read_bytes(conn, count):
    buff = bytearray()
    while len(buff) < count:
        leftover = count - len(buff)
        buff += conn.recv(leftover)
    return bytes(buff)


if __name__ == '__main__':
    main()
