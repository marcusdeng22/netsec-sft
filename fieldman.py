
import socket
import hashlib
import binascii

HOST = 'localhost'
PORT = 45678

SECRET_KEY = '0123456789abcdef'
print(SECRET_KEY)

bitstring = ''
for c in SECRET_KEY:
    bitstring += '{0:04b}'.format(int(c, 16))
print(bitstring, len(bitstring))

print(int(SECRET_KEY, 16))
print(int(bitstring, 2))

SECRET_KEY = int(SECRET_KEY, 16)
print(SECRET_KEY ^ SECRET_KEY)

'''
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    while True:  # Using break statement to emulate do-while loop.

        to_send = input(":> ")
        if to_send == 'quit' or \
            to_send == 'exit' or \
            to_send == 'q':
            break

        s.sendall(bytes(to_send, 'utf-8'))
'''