
import socket
import hashlib
import binascii

HOST = 'localhost'
PORT = 45678


# Make a dumb secret key
SECRET_KEY = '0123456789abcdef'
print(SECRET_KEY)

key_bitstring = ''
for c in SECRET_KEY:
    key_bitstring += '{0:04b}'.format(int(c, 16))
#print(bitstring)

for i in range(0, len(key_bitstring), 8):
    print(key_bitstring[i:i+8], end=' ')
print(len(key_bitstring))

#print(int(SECRET_KEY, 16))
#print(int(bitstring, 2))

SECRET_KEY = int(SECRET_KEY, 16)
#print(SECRET_KEY ^ SECRET_KEY)


length_to_print = 8

secret_message = 'The man in Black fled across the Desert, and the Gunslinger followed.'
for c in secret_message[:length_to_print]:
    print('{0:>8}'.format(c), end=' ')
print()


# Convert the string to hex
secret_chars = [binascii.hexlify(c.encode('utf-8')) for c in secret_message]

# Check out some print formattings
for i in secret_chars[:length_to_print]:
    print('{0:8x}'.format(int(i, 16)), end=' ')
print()

for i in secret_chars[:length_to_print]:
    print('{0:8}'.format(int(i, 16)), end=' ')
print()

for i in secret_chars[:length_to_print]:
    print('{0:08b}'.format(int(i, 16)), end=' ')
print('\n')


# Can't ''.join the elements of the SECRET_CHARS list because they
#   are all encoded and something goes wrong decoding them blah blah.
# So, combine the elements into a 64 bit bitstring 8 bits at a time
#   and combine them.
bitstring = ''
for c in secret_chars[:8]:
    bitstring += '{0:08b}'.format(int(c, 16))
#print(bitstring)

# for i in range(0, len(bitstring), 8):
#     print(SECRET_NUMS[i:i+8], end=' ')
# print(len(SECRET_NUMS))


# We have successfully converted the message into an integer.
secret_nums = int(bitstring, 2)
print(secret_nums)
print(bitstring)
print('{0:0>64b}'.format(secret_nums))
print()


# We have a secret block, finally.
print('{0:0>64b}'.format(secret_nums))
print('{0:0>64b}'.format(SECRET_KEY))
secret_block = secret_nums ^ SECRET_KEY
print('{0:0>64b}'.format(secret_block))


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
