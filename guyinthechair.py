
# Server

import socket


def main():
    SECRET_KEY = '0123456789abcdef'
    block_size_bytes = len(SECRET_KEY) // 2
    SECRET_KEY = int(SECRET_KEY, 16)
    print('{0:0>{1}b}'.format(SECRET_KEY, block_size_bytes*8))

    HOST = 'localhost'
    PORT = 45678
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()  # Sets the server to listen for incoming requests

        print("\nListening for incoming connections\n")
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
                while len(buff) >= block_size_bytes:
                    # Receive a block of encrypted bytes. Each byte is one bit of the bitstring.
                    encrypted_bytes, buff = buff[:block_size_bytes*8], buff[block_size_bytes*8:]
                    #print('Encrypted bytes:', encrypted_bytes)

                    # Decode the encrypted bytes to get a bitstring. Each character is one bit.
                    encrypted_bitstring = encrypted_bytes.decode('utf-8')
                    #print('Encrypted bitstring:', encrypted_bitstring)
                    
                    # Convert the bitstring into an integer
                    encrypted_int = int(encrypted_bitstring, 2)
                    #print('Encrypted integer: {0:0>{1}b}'.format(encrypted_int, block_size_bytes*8))

                    # Decrypt it by XOR'ing it with the key.
                    decrypted_int = encrypted_int ^ SECRET_KEY
                    #print('Decrypted integer: {0:0>{1}b}'.format(decrypted_int, block_size_bytes*8))

                    # Break down the integer into a list of individual ints (so we can
                    # convert it back into a bytes object).
                    #print()
                    int_list = []
                    for i in range(block_size_bytes):
                        # Take the 8 LSB and insert it at front of list
                        lsb = 0b11111111 & decrypted_int
                        int_list.insert(0, lsb)
                        #print('{a:0{b}b} {c:08b} {d}'.format(a=decrypted_int, b=(block_size_bytes*8)-(i*8), c=lsb, d=int_list[0]))
                        decrypted_int >>= 8  # Until decrypted_int is no more

                    # Convert list_int into a bytes object.
                    to_file = bytes(int_list)
                    print("to_file: {0}".format(to_file))
                
            # Deal with the last less-than-block_size bytes of data
            print('\"', buff.decode('utf-8'), '\"\nfinished.', sep='')
                

if __name__ == '__main__':
    print("hello there, fool!")
    main()
