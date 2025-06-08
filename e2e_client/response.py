import struct
from enum import Enum
import time
from cryptohelper import CryptoHelper


class ResponseCode(Enum):
    REGISTER_SUCCESS = 200
    RECONNECT_SUCCESS = 201
    SHARE_PUBLIC_KEYS = 202
    MESSAGE_TRANSFER_SUCCESS = 203
    END_USER_OFFLINE = 204
    SEND_MESSAGE = 103


class Payload():
    pass


class EmptyPayload(Payload):
    """EmptyPayload is a derived class of Payload that represents an empty payload """

    def __init__(self):
        pass

    def get_bytes(self):
        return b''

    def __len__(self):
        return 0


class EncryptedPublicKeysPayload(Payload):
    """
    EncryptedPublicKeysPayload is a derived class of Payload that represents a payload containing encrypted public keys along with AES key and IV.

    Attributes:
        aes_key (bytes): The AES key used for encryption.
        aes_iv (bytes): The AES initialization vector used for encryption.
        encrypted_pub_keys (bytes): The AES encrypted public keys list.
    """

    def __init__(self, aes_key, aes_iv, encrypted_pub_keys):
        self.aes_key = aes_key
        self.aes_iv = aes_iv
        self.encrypted_pub_keys = encrypted_pub_keys

    def get_aes_key(self):
        return self.aes_key

    def get_aes_iv(self):
        return self.aes_iv

    def get_encrypted_pub_key(self):
        return self.encrypted_pub_keys

    def get_bytes(self):
        return self.aes_key + self.aes_iv + self.encrypted_pub_keys


class MessagePayload(Payload):
    """MessagePayload is a derived class of Payload that represents the payload of a message request"""

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

    def __len__(self):
        return len(self.aes_key) + len(self.aes_iv) + len(self.encrypted_message)

    def get_bytes(self):
        return self.aes_key + self.aes_iv + self.encrypted_message


class Response:
    def __init__(self, phone_id, dest_phone_id, code, timestamp, payload_size, payload: Payload, hash):
        self.phone_id = phone_id
        self.dest_phone_id = dest_phone_id
        self.code = code
        self.timestamp = timestamp
        self.payload_size = payload_size
        self.payload = payload
        self.hash = hash

    def get_phone_id(self):
        return self.phone_id

    def get_dest_phone_id(self):
        return self.dest_phone_id

    def get_code(self):
        return self.code

    def get_timestamp(self):
        return self.timestamp

    def get_payload_size(self):
        return self.payload_size

    def get_header_bytes(self):
        return self.phone_id + self.dest_phone_id + self.code.to_bytes(1, "little") + self.timestamp.to_bytes(4, "little") + self.payload_size.to_bytes(4, "little")

    def get_payload(self) -> Payload:
        return self.payload

    def get_hash(self):
        return self.hash

    def compare_hash(self, hash):
        return self.hash == hash
