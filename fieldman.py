
# Client

import socket


def main():
    SECRET_KEY = '0123456789abcdef'
        # Must be of even length. Each character only creates 4 bits of an integer,
        # and reading a file creates a bytes object, where each byte element
        # is 8 bits (obviously).
    block_size_bytes = len(SECRET_KEY) // 2
    SECRET_KEY = int(SECRET_KEY, 16)
    print('{0:0>{1}b}'.format(SECRET_KEY, block_size_bytes*8))
    print()

    HOST = 'localhost'
    PORT = 45678
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

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
                    print("from_file: {0} ({1} bytes), finished".format(from_file, num_bytes))
                    
                    shift = block_size_bytes - num_bytes
                    cipherbytes = encrypt(SECRET_KEY, from_file, num_bytes, shift)

                    s.sendall(cipherbytes)
                    break
                
                # else, process one block of bytes at a time.
                print("from_file: {0}".format(from_file))

                cipherbytes = encrypt(SECRET_KEY, from_file, num_bytes)

                # Send over network.
                s.sendall(cipherbytes)


def encrypt(secret_key, plainbytes, num_bytes, shift=0):
    
    # Destroy the key until its length is the same as the length of the final block.
    # Technically this is conditional on whether we are on the last block, but
    #   it's a one-liner so this will probably be more efficient.
    secret_key >>= shift*8
    #print('sec_key: {0:0>{1}b}'.format(sec_key, num_bytes*8))

    # Convert it into a proper integer bitstring.
    unencrypted_int = 0
    for idx, byte in enumerate(plainbytes):
        unencrypted_int = (unencrypted_int << 8) | byte
        #print('{a:0{b}b} {c:08b} {d}'.format(a=unencrypted_int, b=idx*8, c=byte, d=byte))
    
    #print('\nUnencrypted integer: {0:0>{1}b}'.format(unencrypted_int, block_size_bytes*8))

    # Encrypt it by XOR'ing it with the key.
    encrypted_int = unencrypted_int ^ secret_key
    #print('Encrypted integer: {0:0>{1}b}'.format(encrypted_int, block_size_bytes*8))

    # Convert it back to a string object (so we can encode it).
    # Each bit is a character.
    encrypted_bitstring = '{0:0>{1}b}'.format(encrypted_int, num_bytes*8)
    #print('Encrypted bitstring:', encrypted_bitstring)

    # Convert to bytes (to send over network).
    # Each bit is a byte.
    cipherbytes = encrypted_bitstring.encode('utf-8')
    #print("Encrypted bytes:", encrypted_bytes)

    return cipherbytes


if __name__ == '__main__':
    main()
