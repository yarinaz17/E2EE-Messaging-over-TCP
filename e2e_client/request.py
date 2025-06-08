from enum import Enum
import struct
from cryptohelper import CryptoHelper


class Op(Enum):
    RECONNECT = 100
    REGISTER = 101
    GET_PUBLIC_KEYS = 102
    SEND_MESSAGE = 103


class Payload():
    pass


class EmptyPayload(Payload):
    """Represents empty payload."""

    def __init__(self):
        pass

    def get_bytes(self):
        return b''

    def __len__(self):
        return 0


class PublicKeyPayload():
    """Represents public key payload (for registration requests)"""

    def __init__(self, pub_key):
        self.pub_key = pub_key

    def get_pub_key(self):
        return self.pub_key

    def get_bytes(self):
        return self.pub_key

    def __len__(self):
        return len(self.pub_key)


class MessagePayload(Payload):
    """Represents message payload (for message requests)"""

    def __init__(self, aes_key, aes_iv, encrypted_message):
        self.aes_key = aes_key
        self.aes_iv = aes_iv
        self.encrypted_message = encrypted_message

    def get_aes_key(self):
        return self.aes_key

    def get_aes_iv(self):
        return self.aes_iv

    def get_encrypted_message(self):
        return self.encrypted_message

    def get_bytes(self):
        return self.aes_key + self.aes_iv + self.encrypted_message

    def __len__(self):
        return len(self.aes_key) + len(self.aes_iv) + len(self.encrypted_message)


class Header:
    """Represents request header"""

    def __init__(self, phone_id, dest_phone_id, code, timestamp, payload_size):
        self.phone_id = phone_id
        self.dest_phone_id = dest_phone_id
        self.code = code.value
        self.timestamp = timestamp
        self.payload_size = payload_size

    def get_phone_id(self):
        return self.phone_id

    def get_code(self):
        return self.code

    def get_timestamp(self):
        return self.timestamp

    def get_dest_phone_id(self):
        return self.dest_phone_id

    def to_bytes(self):
        dest_phone_id_encoded = self.dest_phone_id.encode(
        ) if self.dest_phone_id else b'\0' * 10
        # Ensure dest_phone_id is correctly encoded to 10 bytes, pad with null bytes if None
        header_bytes = struct.pack('<10s10sBII', self.phone_id.encode(), dest_phone_id_encoded, self.code,
                                   self.timestamp, self.payload_size)
        return header_bytes


class Request:
    def __init__(self, phone_id, dest_phone_id, code, timestamp, payload: Payload = None):
        self.headers = Header(phone_id, dest_phone_id,
                              code, timestamp, len(payload))
        self.payload = payload

    def get_payload(self):
        return self.payload

    def get_code(self):
        return self.headers.code

    def _encrypt_payload(self, servers_pub_key, end_user_pub_key=None):
        """
        Encrypts the payload based on the operation code in the headers.

        Args:
            servers_pub_key (bytes): The server's public key used for encryption.
            end_user_pub_key (bytes, optional): The end user's public key used for encryption. Required if the operation code is SEND_MESSAGE.

        Returns:
            bytes: The encrypted payload. For REGISTER operation, returns the public key that is encrypted using server's public key.
                   For SEND_MESSAGE operation, returns the concatenation of the encrypted AES key, AES IV, and the encrypted message (Encrypted using the AES key).
        """
        # If code == Op.REGISTER, then we can assume that the payload is of type PublicKeyPayload
        if self.headers.code == Op.REGISTER.value:
            encrypted_pub_key = CryptoHelper.encrypt_with_public_key(
                self.payload.get_pub_key(), servers_pub_key)
            return encrypted_pub_key

        # If code == Op.SEND_MESSAGE, then we can assume that the payload is of type MessagePayload
        if self.headers.code == Op.SEND_MESSAGE.value:
            encrypted_aes_key = CryptoHelper.encrypt_with_public_key(
                self.payload.get_aes_key(), end_user_pub_key)
            return encrypted_aes_key + self.payload.get_aes_iv() + self.payload.get_encrypted_message()

    def hash_and_encrypt(self, servers_pub_key, clients_priv_key, end_user_pub_key=None):
        """
        This method hashes the non-encrypted request headers and payload,
        then, if it's a message request the AES key inside the payload is encrypted using the 'end_user_pub_key'.
        if it's a registration request the client's public key is encrypted using the server's public key
        Header is always encrypted using the server's public key
        (hash is not encrypted).
        """
        encrypted_payload = b''

        # encrypt the payload first
        if self.headers.payload_size > 0:
            encrypted_payload = self._encrypt_payload(
                servers_pub_key, end_user_pub_key)

        # in case that there is a payload, update the payload size to the size of the encrypted payload
        self.headers.payload_size = len(encrypted_payload)

        # encode the header
        encoded_header = self.headers.to_bytes()

        # encrypt the header
        encrypted_header = CryptoHelper.encrypt_with_public_key(
            encoded_header, servers_pub_key)

        # hash the non-encrypted header + payload
        hash_obj = CryptoHelper.compute_SHA256(
            encoded_header, self.payload.get_bytes())

        # TODO: sign hash with private key
        self.hash = CryptoHelper.sign_with_private_key(
            hash_obj, clients_priv_key)

        return encrypted_header + encrypted_payload + self.hash
