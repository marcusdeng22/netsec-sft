
import sys
import socket
import hashlib
import binascii


length_to_print = 8


def main():
    # Make a dumb secret key
    SECRET_KEY = '0123456789abcdef'
    block_size_bytes = len(SECRET_KEY)
    SECRET_KEY = [binascii.hexlify(c.encode('utf-8')) for c in SECRET_KEY]
    SECRET_KEY = bit_stringify(SECRET_KEY)
    print(SECRET_KEY)



    HOST = 'localhost'
    PORT = 45678
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        with open("input.txt", 'rb') as file:
                
            while True:
                # Read a block of bytes from the file.
                from_file = file.read(block_size_bytes)
                    # Result is a bytes-like object of x bytes, though each element
                    # is an int already.

                if len(from_file) < block_size_bytes:
                    s.sendall(from_file)
                    break
                    # Only XOR as much of the key as there is message.
                    # Shift left or right?
                    

                s.sendall(from_file)





    # secret_message = 'The man in Black fled across the Desert, and the Gunslinger followed.'
    # for c in secret_message[:length_to_print]:
    #     print('{0:>8}'.format(c), end=' ')
    # print()

    # secret_nums = bit_stringify(secret_message)

    # # We have a secret block, finally.
    # print('secret:    {0:0>64b}'.format(secret_nums))
    # print('key:       {0:0>64b}'.format(SECRET_KEY))
    # secret_block = secret_nums ^ SECRET_KEY
    # print('ecnrypted: {0:0>64b}'.format(secret_block))





# Takes the entire message as a string.
# Returns the first eight characters as a number.
#   I wonder if encoding the whole message will produce issues with the
#   number becoming too big? Might be better practice to iterate x bytes
#   at a time instead of the whole message.
def bit_stringify(inp_str):

    # # Convert the string to hex
    # secret_chars = [binascii.hexlify(c.encode('utf-8')) for c in inp_str]

    # # Check out some print formattings
    # for i in secret_chars[:length_to_print]:
    #     print('{0:8x}'.format(int(i, 16)), end=' ')
    # print()

    # for i in secret_chars[:length_to_print]:
    #     print('{0:8}'.format(int(i, 16)), end=' ')
    # print()

    # for i in secret_chars[:length_to_print]:
    #     print('{0:08b}'.format(int(i, 16)), end=' ')
    # print('\n')

    secret_chars = inp_str

    # Combine the elements into a 64 bit bitstring 8 bits at a time
    #   and combine them.
    # Can't ''.join the elements of the SECRET_CHARS list because they
    #   are all encoded and something goes wrong decoding them blah blah.
    bitstring = ''
    for c in secret_chars[:8]:
        bitstring += '{0:08b}'.format(int(c, 16))
    #print(bitstring)

    # for i in range(0, len(bitstring), 8):
    #     print(SECRET_NUMS[i:i+8], end=' ')
    # print(len(SECRET_NUMS))


    # Convert the message into an integer.
    secret_nums = int(bitstring, 2)
    print(secret_nums)
    print(bitstring)
    print('{0:0>64b}'.format(secret_nums))
    print()

    return secret_nums


if __name__ == '__main__':
    main()
