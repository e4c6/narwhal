#!/usr/bin/env python3
# e4c6 ~2020
import threading
import socket
import argparse
import os
from crypto import *
from fluff import narwhal_welcome


class Send(threading.Thread):
    def __init__(self, sock, name, key, pkey, secret, server_pkey):
        super().__init__()
        self.sock = sock
        self.name = name
        self.key = key
        self.pkey = pkey
        self.secret = secret
        self.server_pkey = server_pkey

    def run(self):
        while True:
            message = input('{}: '.format(self.name))
            # Type 'QUIT' to leave the chatroom
            if message == 'QUIT':
                self.sock.sendall('#EXIT#'.encode('ascii'))
                break

            # Send message to server for broadcasting
            else:
                msg = '{}: {}'.format(self.name, message)
                msg = encrypt_message(msg, self.key, self.secret, self.server_pkey)
                self.sock.sendall(str(msg).encode('ascii'))

        print('\nQuitting...')
        self.sock.close()
        os._exit(0)


class Receive(threading.Thread):
    def __init__(self, sock, name, key, pkey, secret, server_pubkey):
        super().__init__()
        self.sock = sock
        self.name = name
        self.key = key
        self.pkey = pkey
        self.secret = secret
        self.server_pkey = server_pubkey

    def run(self):
        while True:
            message = self.sock.recv(4096)
            if message:
                msg = decrypt_message(message.decode('ascii'), self.key, self.secret)
                print('\r{}\n{}: '.format(msg, self.name), end='')
            # else:
            #     # Server has closed the socket, exit the program
            #     print('\nFuck, we have lost connection to the server!')
            #     print('\nQuitting...')
            #     self.sock.close()
            #     os._exit(0)


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secret = generate_password(256)
        self.key, self.pubkey = generate_key(self.secret, "client@narwhal", 365)
        self.server_pubkey = None

    def exchange_keys(self):
        self.sock.connect((self.host, self.port))
        print('[+] Requesting public key from server...')
        self.sock.sendall('#REQUEST_KEY#'.encode('ascii'))
        while True:
            message = self.sock.recv(4096).decode('ascii')
            if message.startswith('#SERVER_PUBKEY#'):
                print('[+] Received public key from server...')
                self.server_pubkey = message.split('#SERVER_PUBKEY#')[1]
                self.server_pubkey, _ = pgpy.PGPKey.from_blob(self.server_pubkey)
                print('[+] Requesting challenge from server...')
                self.sock.sendall(('#REQUEST_CHALLENGE#' + str(self.pubkey)).encode('ascii'))
            if message.startswith('#CHALLENGE#'):
                print('[+] Received challenge from server...')
                challenge = message.split('#CHALLENGE#')[1]
                challenge_dec = decrypt_message(challenge, self.key, self.secret)
                print('[+] Successfully decrypted challenge...')
                encrypt_challenge_response = encrypt_message(challenge_dec, self.key, self.secret, self.server_pubkey)
                print('[+] Sending challenge solution to server...')
                self.sock.sendall(('#CHALLENGE_RESPONSE#'+str(encrypt_challenge_response)).encode('ascii'))
            if message.startswith('#WELL DONE#'):
                print('[+] Server approved solution...')
                print('[+] Migrating to chatroom...')
                break

    def start(self):
        print(narwhal_welcome)
        name = input('Your name: ')
        print()
        print('Welcome, {}! Getting ready to send and receive messages...'.format(name))
        # Create send and receive threads
        send = Send(self.sock, name, self.key, self.pubkey, self.secret, self.server_pubkey)
        receive = Receive(self.sock, name, self.key, self.pubkey, self.secret, self.server_pubkey)
        # Start send and receive threads
        send.start()
        receive.start()
        print("\rAll set! Leave the chatroom anytime by typing 'QUIT'\n")
        print('{}: '.format(name), end='')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Narwhal PGP Chat')
    parser.add_argument('host', help='Interface the server listens at')
    parser.add_argument('-p', metavar='PORT', type=int, default=1060,
                        help='TCP port (default 1060)')
    args = parser.parse_args()
    client = Client(args.host, args.p)
    client.exchange_keys()
    client.start()
