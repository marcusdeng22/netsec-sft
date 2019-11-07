
import socket

HOST = 'localhost'
PORT = 45678

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    to_send = input(":> ")

    s.sendall(bytes(to_send, 'utf-8'))
