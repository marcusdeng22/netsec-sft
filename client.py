
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
    USAGE = 'Usage: python client.py <mode> <file> where mode is "up" or "down" for upload or download, and file is the name of the file'
    # get command line arguments
    if len(sys.argv) != 3:
        print(USAGE)
        return
    MODE = sys.argv[1]
    if MODE not in ["up", "down"]:
        print(USAGE)
        return
    FILE = sys.argv[2]  # assumes files exist already: minimal error checking on client or server for nonexistent file
    if (len(FILE) > 1024):
        print("Maximum file name size is 1024")
        return

    BLOCK_SIZE_BYTES = 16

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
        temp_mode = ' ' * (BLOCK_SIZE_BYTES - len(MODE) - 1) + MODE

        print(len(FILE))
        file_name_len_blocks = len(FILE) // BLOCK_SIZE_BYTES + 1
        file_name_padding = BLOCK_SIZE_BYTES - len(FILE) % BLOCK_SIZE_BYTES
        print(file_name_padding)
        temp_file = FILE + ' ' * file_name_padding
        
        temp_mode_bytes = bytearray()
        temp_mode_bytes += chr(file_name_len_blocks).encode('utf-8') + temp_mode.encode('utf-8')
        
        print(temp_mode_bytes)
        s.sendall(temp_mode_bytes)

        return
        
        combined = temp_mode + temp_file

        extra_block = IV
        for i in range(len(combined) / BLOCK_SIZE_BYTES):
            key_bytes = genOTP(SECRET_KEY, extra_block, BLOCK_SIZE_BYTES)
            encrypted_bytes = XOR_bytes(key_bytes, combined[i*BLOCK_SIZE_BYTES:(i+1)*BLOCK_SIZE_BYTES])

            s.sendall(encrypted_bytes)

            extra_block = encrypted_bytes


            

        
        s.sendall(temp_mode.encode("utf-8"))

        s.sendall(temp_file.encode("utf-8"))

        # select mode, and execute
        if MODE == "up":
            if not send_file(FILE, SECRET_KEY, extra_block, BLOCK_SIZE_BYTES, s):
                print("failed to upload; check if file exists")
            else:
                print("file uploaded")
        elif MODE == "down":
            FILE = FILE.split('.')    # For testing
            FILE = FILE[0] + "_testing." + FILE[1]
            if not recv_file(FILE, SECRET_KEY, extra_block, BLOCK_SIZE_BYTES, s):
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
            print("Successfully authenticated server!")
            return True
        else:
            print("Failed to authenticate server")
            return False


if __name__ == '__main__':
    main()
