
import socket
import struct
from cryptohelper import CryptoHelper
from request import *
from response import Response


FIXED_HEADER_SIZE = 256
RSA_KEY_LEN = 256
LEN_SIGNED_HASH_FROM_CLIENT = 128


class Connection:

    """This class serves for handling the connection with the clients. Each session with client is associated with a unique connection object through which the communication is done."""

    def __init__(self, sock: socket.socket, server_private_key):
        self.sock = sock
        # Server's private key is used for signing hashes
        self.server_private_key = server_private_key
        self.IS_OPEN = True

    def set_endpoint_public_key(self, public_key):
        """
        This method sets the public key of the endpoint client associated with this connection object.
        The public key is needed for encrypting response / message headers and payloads"""
        self.endpoint_public_key = public_key

    def get_endpoint_public_key(self):
        return self.endpoint_public_key

    def _parse_payload(self, code, encrypted_payload):
        """
        Parses the payload received from the client based on the operation code.

        Args:
            code (int): The operation code indicating the type of payload.
            encrypted_payload (bytes): The encrypted payload data received from the client.

        Returns:
            The parsed payload object based on the operation code (RegisterPayload or MessagePayload).

        """
        """This method reads the payload from the client"""
        if code == Op.REGISTER.value:
            # Decrypt the payload
            public_key = CryptoHelper.decrypt_with_private_key(
                encrypted_payload, self.server_private_key)
            return RegisterPayload(public_key)

        if code == Op.SEND_MESSAGE.value:
            payload = MessagePayload(
                encrypted_payload[:RSA_KEY_LEN], encrypted_payload[RSA_KEY_LEN:RSA_KEY_LEN+16], encrypted_payload[RSA_KEY_LEN+16:])
            return payload

    def read_request(self):
        """
        Reads bytes from the socket and returns a request object constructed from these bytes.

        This method performs the following steps:
        1. Reads an encrypted header from the socket.
        2. Decrypts the header using the server's private key.
        3. Unpacks the decrypted header to extract phone IDs, code, timestamp, and payload size.
        4. If there is a payload, reads the encrypted payload from the socket and parses it.
        5. Reads the signed hash from the socket.
        6. Constructs and returns a Request object using the extracted and parsed data.

        Raises an exception if connection is closed by the peer or if unexpected number of bytes has been read:

        Returns:
            Request: A request object containing the extracted and parsed data.
        """

        try:
            encrypted_header = self.sock.recv(RSA_KEY_LEN)
        except ConnectionResetError:
            self.IS_OPEN = False
            raise ConnectionResetError("Connection Reset Error")

        if len(encrypted_header) == 0:
            self.IS_OPEN = False
            raise Exception("Connection closed by peer")

        if len(encrypted_header) != RSA_KEY_LEN:
            raise ValueError(
                f"Expected {RSA_KEY_LEN} bytes, but got {len(encrypted_header)}")

        # decrypt header
        decrypted_header = CryptoHelper.decrypt_with_private_key(
            encrypted_header, self.server_private_key)
        # Unpack
        phone_id, dest_phone_id, code, timestamp, payload_size = struct.unpack(
            '<10s 10s B I I', decrypted_header)

        # All requests that have a payload goes through this block
        if payload_size > 0:
            # Read payload
            encrypted_payload = self.sock.recv(payload_size)

            payload = self._parse_payload(code, encrypted_payload)
        else:
            payload = EmptyPayload()
        # Read hash
        # The request handler will drop the request in case the hash is bad
        hash = self.sock.recv(LEN_SIGNED_HASH_FROM_CLIENT)

        req = Request(phone_id, dest_phone_id, code,
                      timestamp, payload_size, payload, hash)

        return req

    def close(self):
        # Close the socket
        if self.sock:
            self.sock.close()
            self.sock = None
            self.IS_OPEN = False

    def is_open(self):
        return self.IS_OPEN

    def forward_request(self, request: Request):
        """
        Forwards a message request to the end-user.

        This method serializes the request header, encrypts it using the endpoint's public key,
        and sends the encrypted header along with the payload and hash through the socket.

        Args:
            request (Request): The message request to be forwarded. 

        Raises an exception if the socket is closed and the message cannot be sent.
        """
        # Serialize the request header
        header = struct.pack('<10s 10s B I I', request.phone_id,
                             request.dest_phone_id, request.opcode, request.timestamp, request.payload_size)

        # Payload has already been encrypted by the sender
        payload = request.payload.get_bytes()
        hash = request.hash

        encrypted_header = CryptoHelper.encrypt_with_public_key(
            header, self.endpoint_public_key)

        try:
            self.sock.sendall(encrypted_header+payload+hash)
        except:
            self.IS_OPEN = False
            raise ConnectionError("Socket is closed")

    def send_response(self, response: Response):
        """
        Sends a response to the client.

        Args:
            response (Response): The response object to be sent to the client.

        Raises an exception if the socket is closed or an error occurs during sending.
        """

        # send the serialized response
        try:
            self.sock.sendall(response.hash_and_encrypt(self.server_private_key,
                                                        self.endpoint_public_key))
        except:
            self.IS_OPEN = False
            raise ConnectionError("Socket is closed")
