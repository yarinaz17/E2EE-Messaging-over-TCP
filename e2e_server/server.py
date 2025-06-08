import socket
import threading
from client import Client
from connection import Connection
from cryptohelper import *
from requesthandler import RequestHandler


class Server:

    pending = []

    def __init__(self, port):
        self.port = port
        self.private_key = CryptoHelper.read_private_key()

    def start(self):
        print("[SERVER] Starting ...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serversocket:
            # bind the socket to localhost
            serversocket.bind(('127.0.0.1', self.port))
            print(f"[SERVER] Server is listening on 127.0.0.1:{self.port}")
            # start listening
            serversocket.listen(5)

            while True:
                # accept connections from outside
                (clientsocket, address) = serversocket.accept()
                print(f"[SERVER] New connection approved from : {address}")

                # create new connection object
                conn = Connection(clientsocket, self.private_key)

                # handle the new incoming connection on a new thread
                ct = threading.Thread(
                    target=self.handle_connection, args=(conn,))
                ct.start()

    def handle_connection(self, conn: Connection):
        # while client is connected perform :
        #   1. Read request from socket using the 'Connection' object
        #   2. Pass request to the RequestHandler
        #   3. The RequestHandler will handle the request and will return a Response object
        #   4. Pass the response object from stage 3 to the 'Connection' object so it can be sent through the socket
        #  (*) Break from the loop when the client disconnects or when it sends a bad request
        handler = RequestHandler()
        while True:
            try:
                request = conn.read_request()
            except Exception as ex:
                print(f"Exception {type(ex).__name__} occurred. {ex.args}")
                print("[SERVER] Connection with peer has been terminated")
                conn.close()
                break
            if request != None:
                response = handler.handle_request(conn, request)

            if response != None:
                conn.send_response(response)
            else:
                print(
                    "[SERVER] Received bad request / hash mismatch, closing connection with client")
                conn.close()
                break
