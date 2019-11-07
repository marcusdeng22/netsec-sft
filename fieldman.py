
import socket

HOST = 'localhost'
PORT = 45678

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    while True:  # Using break statement to emulate do-while loop.

        to_send = input(":> ")
        if to_send == 'quit' or \
            to_send == 'exit' or \
            to_send == 'q':
            break

        s.sendall(bytes(to_send, 'utf-8'))
