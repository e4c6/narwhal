#!/usr/bin/env python3
import time
import threading
import socket
import argparse
import os
from crypto import *


class Server(threading.Thread):
    """
    Supports management of server connections.

    Attributes:
        connections (list): A list of ServerSocket objects representing the active connections.
        host (str): The IP address of the listening socket.
        port (int): The port number of the listening socket.
    """

    def __init__(self, host, port):
        super().__init__()
        self.connections = []
        self.host = host
        self.port = port
        self.secret = generate_password(256)
        self.key, self.pkey = generate_key(self.secret, "server@narwhal", 365)

    def run(self):
        """
        Creates the listening socket. The listening socket will use the SO_REUSEADDR option to
        allow binding to a previously-used socket address. This is a small-scale application which
        only supports one waiting connection at a time.
        For each new connection, a ServerSocket thread is started to facilitate communications with
        that particular client. All ServerSocket objects are stored in the connections attribute.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))

        sock.listen(1)
        print('Listening at', sock.getsockname())

        while True:
            # Accept new connection
            sc, sockname = sock.accept()
            print('Accepted a new connection from {} to {}'.format(sc.getpeername(), sc.getsockname()))

            # Create new thread
            server_socket = ServerSocket(sc, sockname, self)

            # Start new thread
            server_socket.start()

            # Add thread to active connections
            self.connections.append(server_socket)
            print('Ready to receive messages from', sc.getpeername())

    def broadcast(self, message, source):
        """
        Sends a message to all connected clients, except the source of the message.

        Args:
            message (str): The message to broadcast.
            source (tuple): The socket address of the source client.
        """
        for connection in self.connections:

            # Send to all connected clients except the source client
            if connection.sockname != source:
                if len(message) != 0:
                    dec_mes = decrypt_message(message, self.key, self.secret)
                    enc_mes = encrypt_message(dec_mes, self.key, self.secret, connection.pubkey)
                    connection.send(str(enc_mes))

    def send_server_pubkey(self, sockname):
        for connection in self.connections:
            if connection.sockname == sockname:
                connection.send(('#SERVER_PUBKEY#'+str(self.pkey)))

    def challenge_client_pubkey(self, sockname, client_pubkey):
        random_key = generate_password(64)
        encrypted_challenge = encrypt_message(random_key, self.key, self.secret, client_pubkey)
        for connection in self.connections:
            if connection.sockname == sockname:
                connection.send('#CHALLENGE#'+str(encrypted_challenge))
        return random_key

    def validate_challenge_response(self, sockname, challenge, challenge_response):
        print(challenge_response)
        decrypt_response = decrypt_message(str(challenge_response), self.key, self.secret)
        if decrypt_response == challenge:
            for connection in self.connections:
                if connection.sockname == sockname:
                    connection.send('#WELL DONE#')
            return True
        return False

    def remove_connection(self, connection):
        """
        Removes a ServerSocket thread from the connections attribute.

        Args:
            connection (ServerSocket): The ServerSocket thread to remove.
        """
        self.connections.remove(connection)


class ServerSocket(threading.Thread):
    """
    Supports communications with a connected client.

    Attributes:
        sc (socket.socket): The connected socket.
        sockname (tuple): The client socket address.
        server (Server): The parent thread.
    """

    def __init__(self, sc, sockname, server):
        super().__init__()
        self.sc = sc
        self.sockname = sockname
        self.server = server
        self.pubkey = None
        self.challenge = None
        self.has_passed_challenge = False

    def exchange_keys(self, message):
        """
        PGP key exchange flow.
        """
        try:
            if message.startswith('#REQUEST_KEY#'):
                print('Sending pubkey to client...')
                self.server.send_server_pubkey(self.sockname)
            elif message.startswith('#REQUEST_CHALLENGE#'):
                print('Sending challenge to client...')
                client_pubkey = message.split('#REQUEST_CHALLENGE#')[1]
                client_pubkey, _ = pgpy.PGPKey.from_blob(client_pubkey)
                self.pubkey = client_pubkey
                self.challenge = self.server.challenge_client_pubkey(self.sockname, client_pubkey)
            elif message.startswith('#CHALLENGE_RESPONSE#'):
                print('Validating response from client...')
                challenge_response = message.split('#CHALLENGE_RESPONSE#')[1]
                result = self.server.validate_challenge_response(self.sockname, self.challenge, challenge_response)
                if result:
                    self.has_passed_challenge = result
                # prevent multiple attempts
                else:
                    self.challenge = None
        except Exception as e:
            print(message)
            print(e)
            #self.sc.close()
            #server.remove_connection(self)
            return

    def run(self):
        """
        Receives data from the connected client and broadcasts the message to all other clients.
        If the client has left the connection, closes the connected socket and removes itself
        from the list of ServerSocket threads in the parent Server thread.
        """
        while True:
            if self.has_passed_challenge is False:
                message = self.recv_timeout(self.sc)
                self.exchange_keys(message)
                self.sc.setblocking(1)
            elif self.has_passed_challenge is True:
                message = self.recv_timeout(self.sc)
                self.sc.setblocking(1)
                self.server.broadcast(message, self.sockname)
            else:
                # Client has closed the socket, exit the thread
                print('{} has closed the connection'.format(self.sockname))
                self.sc.close()
                server.remove_connection(self)
                return

    def send(self, message):
        """
        Sends a message to the connected server.

        Args:
            message (str): The message to be sent.
        """
        self.sc.sendall(message.encode('ascii'))

    def recv_timeout(self, the_socket, timeout=2):
        # make socket non blocking
        the_socket.setblocking(0)

        # total data partwise in an array
        total_data = [];
        data = '';

        # beginning time
        begin = time.time()
        while 1:
            # if you got some data, then break after timeout
            if total_data and time.time() - begin > timeout:
                break

            # if you got no data at all, wait a little longer, twice the timeout
            elif time.time() - begin > timeout * 2:
                break

            # recv something
            try:
                data = the_socket.recv(4096)
                if data:
                    total_data.append(data)
                    # change the beginning time for measurement
                    begin = time.time()
                else:
                    # sleep for sometime to indicate a gap
                    time.sleep(0.1)
            except:
                pass

        # join all parts to make final string
        return b''.join(total_data).decode('ascii')


def exit(server):
    """
    Allows the server administrator to shut down the server.
    Typing 'q' in the command line will close all active connections and exit the application.
    """
    while True:
        ipt = input('')
        if ipt == 'q':
            print('Closing all connections...')
            for connection in server.connections:
                connection.sc.close()
            print('Shutting down the server...')
            os._exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Chatroom Server')
    parser.add_argument('host', help='Interface the server listens at')
    parser.add_argument('-p', metavar='PORT', type=int, default=1060,
                        help='TCP port (default 1060)')
    args = parser.parse_args()

    # Create and start server thread
    server = Server(args.host, args.p)
    server.start()

    exit = threading.Thread(target=exit, args=(server,))
    exit.start()
