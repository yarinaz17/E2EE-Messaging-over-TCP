import socket
import struct
from request import Request, Op
from response import *
from Crypto.PublicKey import RSA
from cryptohelper import CryptoHelper

RSA_KEY_LEN = 128
LEN_SIGNED_HASH_FROM_SERVER = 256
LEN_SIGNED_HASH_FROM_CLIENT = 128


class Connection:
    """This class serves for handling the encrypted communication with the server"""

    def __init__(self, host, port, server_public_key, clients_priv_key):
        self.host = host
        self.port = port
        # Server's public key is used for encrypting request headers and some of the requests payloads
        self.server_public_key = server_public_key
        # Client's private key is used for signing hashes and decrypting incoming responses
        self.clients_priv_key = clients_priv_key
        # This dictionary will hold users public keys
        self.keys_dict = None

    def set_keys_dict(self, keys_string):
        """Set the public keys dictionary (holds all users public keys)"""
        if not keys_string:
            self.keys_dict = {}
            return
        try:
            self.keys_dict = {}
            for item in keys_string.split(","):
                key, value = item.split(":", 1)
                self.keys_dict[key] = RSA.import_key(
                    bytes.fromhex(value))
        except Exception as ex:
            print(f"Exception {type(ex).__name__} occurred. {ex.args}")
            print("Error creating keys dict")
            self.keys_dict = {}

    def set_end_user(self, dest_phone_id):
        """This method sets the end-user for the current session. Returns True if successful, False otherwise."""
        if self.keys_dict is None:
            return False
        pub_key = self.keys_dict.get(dest_phone_id)
        if pub_key:
            self.set_recipient_public_key(pub_key)
            return True
        else:
            return False

    def get_public_key_from_keys_dict(self, dest_phone_id):
        pub_key = self.keys_dict.get(dest_phone_id)
        return pub_key

    def open(self):
        # Create and connect the socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

    def is_open(self):
        # Checks if connection is open
        return self.sock is not None

    def close(self):
        # Close the socket if it is open
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def send_request(self, request: Request):
        """
        Sends a request to the server through the established socket connection.

        Args:
            request (Request): The request object to be sent.

        Raises:
            Exception: If the socket connection is not open.

        Notes:
            - If the request is a message (identified by Op.SEND_MESSAGE.value), 
              the AES key inside the payload is encrypted with the recipient's public key before sending.
            - Request header is always encrypted using the server's public key 
        """
        if self.sock is None:
            raise Exception("Connection is not open")
        # Send the request
        # If the request is a message, encrypt its payload with the recipient's public key
        if request.get_code() == Op.SEND_MESSAGE.value:
            self.sock.sendall(request.hash_and_encrypt(
                self.server_public_key, self.clients_priv_key, self.recipient_public_key))
        else:
            self.sock.sendall(request.hash_and_encrypt(
                self.server_public_key, self.clients_priv_key))

    def set_recipient_public_key(self, recipient_public_key):
        self.recipient_public_key = recipient_public_key

    def get_recipient_public_key(self):
        return self.recipient_public_key

    def _extract_payload(self, encrypted_payload, code):
        """
        Extracts and decrypts the payload from the encrypted payload based on the response code.

        Args:
            encrypted_payload (bytes): The encrypted payload received.
            code (int): The response code indicating the type of payload.

        Returns:
                - EncryptedPublicKeyPayload: If the response code is SHARE_PUBLIC_KEYS.
                - MessagePayload: If the response code is SEND_MESSAGE.
                - EmptyPayload: If the response code is not one of the two mentioned above.
        """
        if code == ResponseCode.SHARE_PUBLIC_KEYS.value:
            aes_key = CryptoHelper.decrypt_with_private_key(
                encrypted_payload[:RSA_KEY_LEN], self.clients_priv_key)
            payload = EncryptedPublicKeysPayload(
                aes_key, encrypted_payload[RSA_KEY_LEN:RSA_KEY_LEN+16], encrypted_payload[RSA_KEY_LEN+16:])
            return payload
        elif code == ResponseCode.SEND_MESSAGE.value:
            # Decrypt the AES key using the client's private key
            aes_key = CryptoHelper.decrypt_with_private_key(
                encrypted_payload[:RSA_KEY_LEN], self.clients_priv_key)
            payload = MessagePayload(
                aes_key, encrypted_payload[RSA_KEY_LEN:RSA_KEY_LEN+16], encrypted_payload[RSA_KEY_LEN+16:])
            return payload
        else:
            return EmptyPayload()

    def read_response(self):
        """
        Reads a response from the socket, decrypts the header, and processes the payload.

        Raises:
            Exception: If the connection is not open.

        Returns:
            Response: An object containing the phone ID, destination phone ID, code, timestamp, payload size, payload, and hash.
            None: If the connection is closed or no data is received.
        """
        if self.sock is None:
            raise Exception("Connection is not open")

        encrypted_header = self.sock.recv(RSA_KEY_LEN)

        if len(encrypted_header) == 0:
            self.close()
            return None

        # Decrypt the header
        header = CryptoHelper.decrypt_with_private_key(
            encrypted_header, self.clients_priv_key)

        # Unpack the header
        phone_id, dest_phone_id, code, timestamp, payload_size = struct.unpack(
            '<10s10sBII', header)

        # Receive the payload
        if payload_size > 0:
            encrypted_payload = self.sock.recv(payload_size)
            payload = self._extract_payload(encrypted_payload, code)
        else:
            payload = EmptyPayload()

        # Receive signed hash digest
        if code == Op.SEND_MESSAGE.value:
            hash = self.sock.recv(LEN_SIGNED_HASH_FROM_CLIENT)
        else:
            hash = self.sock.recv(LEN_SIGNED_HASH_FROM_SERVER)

        res = Response(phone_id, dest_phone_id, code,
                       timestamp, payload_size, payload, hash)

        return res
