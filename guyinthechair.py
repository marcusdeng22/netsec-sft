
# Server

import socket


def main():
    HOST = 'localhost'
    PORT = 45678
    block_size_bytes = 16

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()  # Sets the server to listen for incoming requests

        while True:
            print("\nListening for incoming connections")
            conn, addr = s.accept()  # Block here until request received
            # Accepts creates a new socket object that we'll be using to
            # communicate with the client.
            # It's different from the socket the server is using to listen
            # for new connections, as we can see with the different port.

            with conn:
                print("Connection from", addr)
                
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

                    # if we recv'd empty string, client closed connection,
                    if not incoming:
                        break  # so break from loop.
                        # buff will be less than block_size bytes b/c while loop.
                    
                    # else, continue processing data
                    buff += incoming

                    # Want at least block_size bytes to XOR with our key.
                    while len(buff) >= block_size_bytes:
                        work_with, buff = buff[:block_size_bytes], buff[block_size_bytes:]
                        print('\"', work_with.decode('utf-8'), '\"', sep='')
                    
            
                # Deal with the last less-than-block_size bytes of data
                print('\"', buff.decode('utf-8'), '\"\nfinished.', sep='')
                

if __name__ == '__main__':
    print("hello there, fool!")
    main()
