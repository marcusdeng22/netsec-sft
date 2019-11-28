
# Server

import socket
from crypto import genOTP, byteXor, writeFile, readFile
import random

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

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
            # Authenticate client: open private key to decrypt message: secret key concatenated with IV
            with open("private_key.pem", "rb") as key_file:
                PRIVATE_KEY = serialization.load_pem_private_key(
                    key_file.read(), password=None, backend=default_backend())
            enc_auth_token = conn.recv(256)  #32 byte long key + iv encrypted message is 256 bytes
            auth_token = PRIVATE_KEY.decrypt(enc_auth_token,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            SECRET_KEY = auth_token[:16]
            IV = auth_token[16:]
            # create integrity key from received secret key: +1
            INTEGRITY_KEY = bytearray(SECRET_KEY)
            INTEGRITY_KEY[15] += 1
            INTEGRITY_KEY = bytes(INTEGRITY_KEY)
            key_block = genOTP(SECRET_KEY, IV)  # Receive a hex string
            block_size_bytes = len(key_block) // 2
                # Each character only creates 4 bits of an integer, and reading a file
                # creates a bytes object, where each byte element is 8 bits (obviously).
            key_block = int(key_block, 16)  # Create an integer

            # send back verification: SECRET_KEY XOR IV
            # import secrets    #testing for failed authentication
            # IV = secrets.token_bytes(16)
            verification = byteXor(SECRET_KEY, IV)
            conn.sendall(bytes(verification))

            # read the mode and file name from client
            # if no data then our authentication was bad and the client closed the connection
            tempMode = conn.recv(4).decode("utf-8")
            tempFile = conn.recv(1024).decode("utf-8")
            MODE = tempMode.strip()
            FILE = tempFile.strip()
            FILE = FILE.split('.')    # For testing
            FILE = FILE[0] + "_testing." + FILE[1]

            print("mode:", MODE)
            print("file:", FILE)

            if MODE == "up":
                if not writeFile(FILE, SECRET_KEY, INTEGRITY_KEY, key_block, block_size_bytes, conn):
                    print("failed to save file")
                else:
                    print("file saved!")
            elif MODE == "down":
                if not readFile(FILE, SECRET_KEY, INTEGRITY_KEY, key_block, block_size_bytes, conn):
                    print("failed to read file")
                else:
                    print("file sent")
            print("done")



if __name__ == '__main__':
    main()
