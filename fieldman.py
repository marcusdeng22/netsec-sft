
# Client

import socket
from crypto import genOTP, crypticate, integrity_hasher


def main():
    SECRET_KEY = '0123456789abcdef'.encode('utf-8')
    IV = 'fedcba9876543210'.encode('utf-8')
    INTEGRITY_KEY = 'ASDF'.encode('utf-8')
    
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

        with open("input.txt", 'rb') as file:
        #with open("pitfalls.pptx", 'rb') as file:
            
            h = integrity_hasher()
                
            while True:
                # Read block_size bytes from the file.
                from_file = file.read(block_size_bytes)
                    # Result is a bytes-like object of x bytes, though each element
                    # is an int already.
                num_bytes = len(from_file)

                # Dump the plainbytes into the integrity hash
                next(h)
                integrity_hash = h.send(from_file)

                # If end of file,
                if num_bytes < block_size_bytes:

                    # Only XOR as much of the key as there is message.
                    shift = block_size_bytes - num_bytes
                    cipherbytes = crypticate(key_block, from_file, shift)

                    key_block = '{0:x}'.format(key_block)[:num_bytes*2]
                    print("from_file: {0} ({1} bytes), enc w {2}, final data hash {3}".format(from_file, num_bytes, key_block, integrity_hash))
                    
                    # Send the last of the encrypted message
                    s.sendall(cipherbytes)
                    #print("cipherbytes:", type(cipherbytes), cipherbytes)

                    # Throw in the secret integrity key and send it off
                    next(h)
                    integrity_hash = h.send(INTEGRITY_KEY)
                    #print(len(integrity_hash))
                    s.sendall(integrity_hash)
                    print('Final keyed hash {0}'.format(integrity_hash))

                    print("Finished")
                    break
                
                # else, process one block of bytes at a time.
                print("from_file: {0}, enc w {1:x}, partial hash {2}".format(from_file, key_block, integrity_hash))

                cipherbytes = crypticate(key_block, from_file)

                # Send over network.
                s.sendall(cipherbytes)
                
                # Generate a block of secret passkey
                key_block = genOTP(SECRET_KEY, cipherbytes)  # Receive a hex string using the ciper block we just created
                key_block = int(key_block, 16)  # Create an integer


if __name__ == '__main__':
    main()
