
# Client

import socket
from crypto import genOTP, byteXor, encrypt, decrypt
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def main():
    # r = random()
    # r.seed(12345)
    # SECRET_KEY = '0123456789abcdef'.encode('utf-8')
    # IV = 'fedcba9876543210'.encode('utf-8')
    SECRET_KEY = secrets.token_bytes(16)
    IV = secrets.token_bytes(16)

    key_block = genOTP(SECRET_KEY, IV)  # Receive a hex string
    block_size_bytes = len(key_block) // 2
        # Each character only creates 4 bits of an integer, and reading a file
        # creates a bytes object, where each byte element is 8 bits (obviously).
    key_block = int(key_block, 16)  # Create an integer
    print('{0:x}'.format(key_block))
    print()


    HOST = 'localhost'
    PORT = 45678
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        with open("public_key.pem", "rb") as key_file:
            PUBLIC_KEY = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        auth_token = PUBLIC_KEY.encrypt(SECRET_KEY + IV, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        print(SECRET_KEY)
        print(IV)
        print(SECRET_KEY + IV)
        print(auth_token)
        print(len(auth_token))
        s.sendall(auth_token)
        print("sent secret key and iv")

        print("verifying...")
        verification = s.recv(16)
        if verification == bytes(byteXor(SECRET_KEY, IV)):
            print("verified!")
        else:
            print("failed to verify")
            return


        with open("input.txt", 'rb') as file:
        #with open("pitfalls.pptx", 'rb') as file:

            while True:
                # Read block_size bytes from the file.
                from_file = file.read(block_size_bytes)
                    # Result is a bytes-like object of x bytes, though each element
                    # is an int already.
                num_bytes = len(from_file)

                # If end of file,
                if len(from_file) < block_size_bytes:
                    # Only XOR as much of the key as there is message.
                    print("from_file: {0} ({1} bytes), enc w {2:x} \nFinished.".format(from_file, num_bytes, key_block))

                    shift = block_size_bytes - num_bytes
                    cipherbytes = encrypt(key_block, from_file, num_bytes, shift)

                    s.sendall(cipherbytes)
                    break

                # else, process one block of bytes at a time.
                print("from_file: {0}, enc w {1:x}".format(from_file, key_block))

                cipherbytes = encrypt(key_block, from_file, num_bytes)

                # Send over network.
                s.sendall(cipherbytes)

                # Generate a block of secret passkey
                key_block = genOTP(SECRET_KEY, cipherbytes)  # Receive a hex string using the ciper block we just created
                key_block = int(key_block, 16)  # Create an integer


if __name__ == '__main__':
    main()
