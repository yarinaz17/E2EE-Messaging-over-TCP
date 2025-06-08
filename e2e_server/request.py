import struct
from enum import Enum


class Op(Enum):
    RECONNECT = 100
    REGISTER = 101
    GET_PUBLIC_KEYS = 102
    SEND_MESSAGE = 103


class Payload:
    pass


class EmptyPayload(Payload):
    """EmptyPayload is a derived class of Payload that represents an empty payload """

    def __init__(self):
        pass

    def get_bytes(self):
        return b''

    def __len__(self):
        return 0


class RegisterPayload(Payload):
    """RegisterPayload is a derived class of Payload that represents the payload of a registration request"""

    def __init__(self, public_key):
        self.public_key = public_key

    def get_bytes(self):
        return self.public_key

    def get_public_key(self):
        return self.public_key


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

    def get_bytes(self):
        return self.aes_key + self.aes_iv + self.encrypted_message

    def __len__(self):
        return len(self.aes_key) + len(self.aes_iv) + len(self.encrypted_message)


class Request:
    def __init__(self, phone_id, dest_phone_id, opcode, timestamp, payload_size, payload: Payload, hash):
        self.phone_id = phone_id
        self.dest_phone_id = dest_phone_id
        self.opcode = opcode
        self.timestamp = timestamp
        self.payload_size = payload_size
        self.payload = payload
        self.hash = hash

    def get_code(self) -> Op:
        return self.opcode

    def get_phone_id(self):
        return self.phone_id

    def get_dest_phone_id(self):
        return self.dest_phone_id

    def get_timestamp(self):
        return self.timestamp

    def get_payload(self):
        return self.payload

    def get_payload_size(self):
        return self.payload_size

    def get_header_bytes(self):
        return self.phone_id + self.dest_phone_id + self.opcode.to_bytes(1, "little") + self.timestamp.to_bytes(4, "little") + self.payload_size.to_bytes(4, "little")

    def get_hash(self):
        return self.hash

    def compare_hash(self, computed_hash):
        return self.hash == computed_hash
