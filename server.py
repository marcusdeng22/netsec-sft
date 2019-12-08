
# Server
import socket

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

            file_name_len_blocks = conn.recv(1)
            # if no data then our authentication was bad and the client closed the connection
            if not file_name_len_blocks:
                print("Authentication failure")
                return

            # Guarantee we read block_size_bytes of mode from client, minus the first byte, which was file_name_length_blocks
            temp_mode = read_bytes(conn, BLOCK_SIZE_BYTES-1)

            # decrypt length and mode
            key_bytes = genOTP(SECRET_KEY, IV, BLOCK_SIZE_BYTES)
            encrypted_bytes = file_name_len_blocks + temp_mode
            decrypted_bytes = XOR_bytes(key_bytes, encrypted_bytes)

            file_name_len_blocks = decrypted_bytes[0]
            mode = decrypted_bytes[1:BLOCK_SIZE_BYTES].decode('utf-8').strip()

            # read the file name from client
            file_name = ''
            for _ in range(file_name_len_blocks):
                key_bytes = genOTP(SECRET_KEY, encrypted_bytes, BLOCK_SIZE_BYTES)

                encrypted_bytes = read_bytes(conn, BLOCK_SIZE_BYTES)

                decrypted_bytes = XOR_bytes(key_bytes, encrypted_bytes)

                file_name += decrypted_bytes.decode('utf-8')

            file_name = file_name.strip()

            if mode == "up":
                file_name = file_name.split('.')    # For testing
                if (len(file_name) >= 2):
                    file_name[-2] += "_server"
                else:
                    file_name[0] += "_server"
                file_name = '.'.join(file_name)
                if not recv_file(file_name, SECRET_KEY, encrypted_bytes, BLOCK_SIZE_BYTES, conn):
                    print("failed to save file")
                else:
                    print("file saved!")
            elif mode == "down":
                if not send_file(file_name, SECRET_KEY, encrypted_bytes, BLOCK_SIZE_BYTES, conn):
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

        # send back verification: SECRET_KEY XOR IV
        verification = XOR_bytes(SECRET_KEY, IV)
        conn.sendall(verification)

        return SECRET_KEY, IV


def read_bytes(conn, count):
    buff = bytearray()
    while len(buff) < count:
        leftover = count - len(buff)
        buff += conn.recv(leftover)
    return bytes(buff)


if __name__ == '__main__':
    main()
