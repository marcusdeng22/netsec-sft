
# Server

import socket
from crypto import genOTP, encrypt, decrypt


def main():
    SECRET_KEY = '0123456789abcdef'.encode('utf-8')
    IV = 'fedcba9876543210'.encode('utf-8')

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
                while num_bytes >= block_size_bytes:
                    # Receive a block of encrypted bytes.
                    encrypted_bytes, buff = buff[:block_size_bytes], buff[block_size_bytes:]
                    num_bytes -= block_size_bytes
                    #print('Encrypted bytes:', encrypted_bytes)

                    plainbytes = decrypt(key_block, encrypted_bytes)
                    
                    print("to_file: {0}, dec w {1:x}".format(plainbytes, key_block))
                    
                    key_block = genOTP(SECRET_KEY, encrypted_bytes)
                    key_block = int(key_block, 16)
                
            # Deal with the last less-than-block_size bytes of data
            #print()
            #num_bytes = len(buff)  # already have from outside while loop.
            #print("num_bytes:", num_bytes)

            shift = block_size_bytes - num_bytes
            plainbytes = decrypt(key_block, buff, shift)
            
            key_block = '{0:x}'.format(key_block)[:num_bytes*2]
            print("to_file: {0} ({1} bytes), dec w {2} \nFinished".format(plainbytes, num_bytes, key_block))


if __name__ == '__main__':
    print("hello there, fool!")
    main()
