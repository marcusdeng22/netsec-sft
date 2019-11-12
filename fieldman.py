
# Client

import socket


def main():
    block_size_bytes = 16

    HOST = 'localhost'
    PORT = 45678
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        with open("input.txt", 'rb') as file:
                
            while True:
                # Read a block_size bytes from the file.
                from_file = file.read(block_size_bytes)
                    # Result is a bytes-like object of x bytes, though each element
                    # is an int already.
                

                # If end of file,
                if len(from_file) < block_size_bytes:
                    s.sendall(from_file)
                    # Only XOR as much of the key as there is message.
                    # Shift left or right?
                    print('\"', from_file.decode('utf-8'), '\"\nfinished.', sep='')

                    break
                
                # else, XOR bytes with key and send block_size bytes of data
                # at a time.
                s.sendall(from_file)
                print('\"', from_file.decode('utf-8'), '\"', sep='')


if __name__ == '__main__':
    main()
