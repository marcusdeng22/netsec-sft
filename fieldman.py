
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
#print(bitstring)

for i in range(0, len(bitstring), 8):
    print(bitstring[i:i+8], end=' ')
print(len(bitstring))

#print(int(SECRET_KEY, 16))
#print(int(bitstring, 2))

SECRET_KEY = int(SECRET_KEY, 16)
#print(SECRET_KEY ^ SECRET_KEY)

length_to_print = 8

SECRET_MESSAGE = 'The man in Black fled across the Desert, and the Gunslinger followed.'
for c in SECRET_MESSAGE[:length_to_print]:
    print('{0:>8}'.format(c), end=' ')
print()


# For some reason this doesn't work?
# SECRET_NUMBERS1 = binascii.hexlify(SECRET_MESSAGE.encode('utf-8'))
# print()
# for i in SECRET_NUMBERS1[:10]:
#     print('{0:>3}'.format(i), end=' ')

SECRET_NUMBERS2 = [binascii.hexlify(c.encode('utf-8')) for c in SECRET_MESSAGE]

for i in SECRET_NUMBERS2[:length_to_print]:
    print('{0:8x}'.format(int(i, 16)), end=' ')
print()

for i in SECRET_NUMBERS2[:length_to_print]:
    print('{0:8}'.format(int(i, 16)), end=' ')
print()

for i in SECRET_NUMBERS2[:length_to_print]:
    print('{0:08b}'.format(int(i, 16)), end=' ')
print('\n')


# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#     s.connect((HOST, PORT))

#     # Iterate over the message block by block in here.
#     #for i in range

#     s.sendall(bytes(SECRET_MESSAGE, 'utf-8'))

#     # while True:  # Using break statement to emulate do-while loop.
#         # to_send = input(":> ")
#         # if to_send == 'quit' or \
#         #     to_send == 'exit' or \
#         #     to_send == 'q':
#         #     break
#         # s.sendall(bytes(to_send, 'utf-8'))
