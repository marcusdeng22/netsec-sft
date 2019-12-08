
# Client

import socket
import secrets
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from crypto import genOTP, XOR_bytes
from utils import send_file, recv_file


def main():
    BLOCK_SIZE_BYTES = 16

    USAGE = 'Usage: python client.py <mode> <file> where mode is "up" or "down" for upload or download, and file is the name of the file'
    # get command line arguments
    if len(sys.argv) != 3:
        print(USAGE)
        return
    mode = sys.argv[1]
    if mode not in ["up", "down"]:
        print(USAGE)
        return
    file_name = sys.argv[2].encode('utf-8')  # assumes files exist already: minimal error checking on client or server for nonexistent file
    if (len(file_name) > BLOCK_SIZE_BYTES*127):
        print("Maximum file name size is", BLOCK_SIZE_BYTES*127)
        return

    # Generate a secret key and IV
    SECRET_KEY = secrets.token_bytes(BLOCK_SIZE_BYTES)
    IV = secrets.token_bytes(BLOCK_SIZE_BYTES)


    HOST = 'localhost'
    PORT = 45678
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
        except:
            print("server is not reachable")
            return

        # Authenticate server
        if not auth_server(s, SECRET_KEY, IV, BLOCK_SIZE_BYTES):
            return

        # send the mode and file name so server knows what to do
        temp_mode = ' ' * (BLOCK_SIZE_BYTES - len(mode) - 1) + mode

        file_name_len_blocks = len(file_name) // BLOCK_SIZE_BYTES + 1
        file_name_padding = BLOCK_SIZE_BYTES - len(file_name) % BLOCK_SIZE_BYTES
        padded_file_name = file_name + (' ' * file_name_padding).encode('utf-8')

        temp_mode_bytes = bytearray()
        temp_mode_bytes += chr(file_name_len_blocks).encode('utf-8') + temp_mode.encode('utf-8')

        # data sent is 16 bytes; 1st byte is the # of blocks to read for the file name, and then the last bytes are for mode
        key_bytes = genOTP(SECRET_KEY, IV, BLOCK_SIZE_BYTES)
        encrypted_bytes = XOR_bytes(key_bytes, temp_mode_bytes)
        s.sendall(encrypted_bytes)


        for i in range(file_name_len_blocks):
            key_bytes = genOTP(SECRET_KEY, encrypted_bytes, BLOCK_SIZE_BYTES)
            encrypted_bytes = XOR_bytes(key_bytes, padded_file_name[i*BLOCK_SIZE_BYTES:(i+1)*BLOCK_SIZE_BYTES])
            s.sendall(encrypted_bytes)


        # select mode, and execute
        if mode == "up":
            if not send_file(file_name, SECRET_KEY, encrypted_bytes, BLOCK_SIZE_BYTES, s):
                print("failed to upload; check if file exists")
            else:
                print("file uploaded")
        elif mode == "down":
            file_name = file_name.decode('utf-8').split('.')    # For testing
            if (len(file_name) >= 2):
                file_name[-2] += "_client"
            else:
                file_name[0] += "_client"
            file_name = '.'.join(file_name)
            if not recv_file(file_name, SECRET_KEY, encrypted_bytes, BLOCK_SIZE_BYTES, s):
                print("failed to download; check if file exists")
            else:
                print("file downloaded")
        print("done")


def auth_server(s, SECRET_KEY, IV, BLOCK_SIZE_BYTES):
    # load public key of server and encrypt a message: SECRET_KEY concatenated with IV
    with open("public_key.pem", "rb") as key_file:
        PUBLIC_KEY = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

        auth_token = PUBLIC_KEY.encrypt(
            SECRET_KEY + IV,
            padding.OAEP(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        s.sendall(auth_token)  # 256 bytes long
        verification = s.recv(BLOCK_SIZE_BYTES)   # XOR of secret key and IV
        if verification == XOR_bytes(SECRET_KEY, IV):
            print("Successfully authenticated server!\n")
            return True
        else:
            print("Failed to authenticate server\n")
            return False


if __name__ == '__main__':
    main()
