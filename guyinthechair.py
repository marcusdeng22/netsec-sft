
# Server

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
        s.bind((HOST, PORT))
        s.listen()  # Sets the server to listen for incoming requests

        print("Listening for incoming connections\n")
        conn, addr = s.accept()  # Block here until request received
        # Accepts creates a new socket object that we'll be using to
        # communicate with the client.
        # It's different from the socket the server is using to listen
        # for new connections, as we can see with the different port.

        with conn:
            #print("Connection from", addr)

            h = integrity_hasher()
            integrity_hash = ''
            
            # maintain two vars, 'buff' and 'incoming'.
            #   recv'ing into 'incoming' instead of immediately appending to
            #       'buff' allows us to check for empty string.
            #   appending to 'buff' instead of immediately recv'ing to 'buff'
            #       allows us to maintain any bytes leftover from while loop
            #       when len(buff) < block_size.

            buff = ''.encode('utf-8')
            # Initialized outside of loop so we can
            #   1. append to it inside of the loop,
            #   2. deal with last less-than-block_size bytes of data after loop.
            
            while True:
                incoming = conn.recv(1024)
                #print(type(incoming))

                # if we recv'd empty string, client closed connection,
                if not incoming:
                    break  # so break from loop.
                    # buff will be less than block_size bytes b/c while loop.
                
                # else, continue processing data

                buff += incoming

                # Want at least block_size bytes to XOR with our key.
                num_bytes = len(buff)
                while num_bytes >= block_size_bytes*2:
                    # Can lookahead for the integrity hash by consuming until *2
                    # Note that this requires the block size and integrity hash to
                    #   be of the same length. Could make it more flexible by multiplying
                    #   by however many times larger the integrity hash is, but then
                    #   on the last block we'd need to consider the case in which the
                    #   hash is smaller, and honestly we're going for simplicity here.

                    # Receive a block of encrypted bytes.
                    encrypted_bytes, buff = buff[:block_size_bytes], buff[block_size_bytes:]
                    num_bytes -= block_size_bytes
                    #print('Encrypted bytes:', encrypted_bytes)

                    plainbytes = crypticate(key_block, encrypted_bytes)

                    next(h)
                    integrity_hash = h.send(plainbytes)
                    
                    print("to_file: {0}, dec w {1:x}, partial hash {2}".format(plainbytes, key_block, integrity_hash))
                    
                    key_block = genOTP(SECRET_KEY, encrypted_bytes)
                    key_block = int(key_block, 16)
                
            # Deal with the last less-than-block_size bytes of data
            #print("buff:", type(buff), buff, len(buff))

            # Get the actual leftover number of data bytes pertaining to the message.
            num_bytes = num_bytes % block_size_bytes
            
            # Break apart the message bytes from the hash bytes
            cryptbytes, hashbytes = buff[:num_bytes], buff[num_bytes:]
            #print(len(cryptbytes), len(hashbytes))
            #print(cryptbytes)
            #print(hashbytes)

            # Decrypt the message bytes
            shift = block_size_bytes - num_bytes
            plainbytes = crypticate(key_block, cryptbytes, shift)
            #print("plainbytes:", plainbytes)

            # Final data hash
            next(h)
            integrity_hash = h.send(plainbytes)

            key_block = '{0:x}'.format(key_block)[:num_bytes*2]
            print("to_file: {0} ({1} bytes), dec w {2}, final data hash {3}".format(plainbytes, num_bytes, key_block, integrity_hash))
            
            next(h)
            integrity_hash = h.send(INTEGRITY_KEY)
            print('Final keyed hash: {0}'.format(integrity_hash))

            print('Received hash: {0}'.format(hashbytes))
            for i in range(len(integrity_hash)):
                if integrity_hash[i] != hashbytes[i]:
                    print("Integrity check failed!")
                    return
            
            print("Integrity check passed!")
            print("Finished")


if __name__ == '__main__':
    print("hello there, fool!")
    main()
