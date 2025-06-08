import time
from connection import Connection
from response import Response
from request import Request
from Crypto.PublicKey import RSA


class Client:
    def __init__(self, conn: Connection, phone_id=None, public_key=None):
        self.conn = conn
        self.phone_id = phone_id
        self.public_key = public_key
        self.pending_messages = []

    def add_pending_message(self, request: Request):
        """
        Adds a request to the list of pending messages.

        Args:
            request (Request): The request object to be added to the pending messages list.
        """
        self.pending_messages.append(request)

    def get_pending_messages(self):
        return self.pending_messages

    def set_phone_id(self, phone_id):
        self.phone_id = phone_id

    def set_public_key(self, public_key):
        self.public_key = RSA.import_key(public_key)

    def set_connection(self, conn):
        self.conn = conn

    def get_phone_id(self):
        return self.phone_id

    def get_public_key(self):
        return self.public_key

    def is_online(self):
        """Checks if client is online by probing the current Connection object that is associated with it."""
        return self.conn.is_open()

    def is_registered(self):
        return self.phone_id != None and self.public_key != None

    def send_response(self, response: Response):
        """
        Sends a response to the client.

        Args:
            response (Response): The response object to be sent.
        """
        try:
            self.conn.send_response(response)
        except ConnectionError:
            pass

    def forward_message(self, request: Request):
        """
        Forwards a message to the client.

        Args:
            request (Request): The request object to be forwarded.

        Returns:
            bool: True if the message was successfully forwarded, False if there was a connection error and the message was added to pending messages.
        """
        try:
            self.conn.forward_request(request)
            return True
        except ConnectionError:
            # TODO: add message to pending messages
            self.pending_messages.append(request)
            return False

    def pending_messages_count(self):
        return len(self.pending_messages)

    def send_pending_messages(self):
        """
        Sends all pending messages.

        This method waits for a short period to allow the reconnection success response to be processed
        before sending all messages that are currently pending. After sending the messages,
        the pending messages list is cleared.

        Note:
        This method is launched on a seperate thread.
        """
        time.sleep(1)
        for message in self.pending_messages:
            self.forward_message(message)
        self.pending_messages = []
