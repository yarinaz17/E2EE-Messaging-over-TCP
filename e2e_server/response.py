import struct
from enum import Enum
import time
from cryptohelper import CryptoHelper
from request import Payload


class ResponseCode(Enum):
    REGISTER_SUCCESS = 200
    RECONNECT_SUCCESS = 201
    SHARE_PUBLIC_KEYS = 202
    MESSAGE_TRANSFER_SUCCESS = 203
    END_USER_OFFLINE = 204


class Payload():
    pass


class EmptyPayload(Payload):
    """EmptyPayload is a class that represents an empty payload """

    def __init__(self):
        pass

    def get_bytes(self):
        return b''

    def __len__(self):
        return 0


class EncryptedPublicKeysPayload(Payload):
    """
    EncryptedPublicKeysPayload is a class that represents a payload containing encrypted public keys along with AES key and IV.

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

    def get_encrypted_pub_keys(self):
        return self.encrypted_pub_keys

    def __len__(self):
        return len(self.aes_key) + len(self.aes_iv) + len(self.encrypted_pub_keys)

    def get_bytes(self):
        return self.aes_key + self.aes_iv + self.encrypted_pub_keys


class Response:
    """Class for representing a response"""

    def __init__(self, dest_phone_id, code, payload: Payload):
        self.phone_id = b'0'*10
        self.dest_phone_id = dest_phone_id
        self.code = code
        self.timestamp = int(time.time())
        self.payload = payload
        self.payload_size = len(self.payload)

    def get_code(self):
        return self.code

    def _encrypt_payload(self, end_user_public_key):
        """
        Encrypts the AES key in the payload using the provided end user's public key.

        The only response that the server sends which has a payload and therefore requires encryption is SHARE_PUBLIC_KEYS.
        This method retrieves the AES key from the payload, encrypts it with the end user's public key,
        and concatenates the encrypted AES key with the AES IV and the encrypted public keys
        from the payload.

        Args:
            end_user_public_key (str): The public key of the end user used to encrypt the AES key.

        Returns:
            bytes: The concatenated result of the encrypted AES key, AES IV, and encrypted public keys.
        """
        if self.code == ResponseCode.SHARE_PUBLIC_KEYS:
            aes_key = self.payload.get_aes_key()
            encrypted_aes_key = CryptoHelper.encrypt_with_public_key(
                aes_key, end_user_public_key)

            return encrypted_aes_key + self.payload.get_aes_iv() + self.payload.get_encrypted_pub_keys()

    def hash_and_encrypt(self, servers_priv_key, end_user_public_key):
        """
        Hashes and encrypts the response payload and header.

        This method performs the following steps:
        1. Encrypts the payload using the end user's public key if the payload exists.
        2. Packs the request fields into a binary format using the struct module.
        3. Computes the SHA-256 hash of the encoded header and payload (before the encryption).
        4. Signs the hash with the server's private key.
        5. Encrypts the header using the end user's public key.
        6. Concatenates the encrypted header, encrypted payload, and signed hash.

        Args:
            servers_priv_key (bytes): The server's private key used for signing the hash.
            end_user_public_key (bytes): The end user's public key used for encrypting the payload and header.

        Returns:
            bytes: The concatenated encrypted header, payload, and signed hash.
        """

        # encrypt payload if it exists
        if self.payload_size > 0:
            payload = self._encrypt_payload(end_user_public_key)
        else:
            payload = b''

        # Pack the request fields into binary format using struct
        encoded_header = struct.pack('<10s10sBII', self.phone_id,
                                     self.dest_phone_id, self.code.value, self.timestamp, len(payload))

        hash_obj = CryptoHelper.compute_SHA256(
            encoded_header, self.payload.get_bytes())

        hash = CryptoHelper.sign_with_private_key(hash_obj, servers_priv_key)

        # Encrypt the header
        encrypted_header = CryptoHelper.encrypt_with_public_key(
            encoded_header, end_user_public_key)

        return encrypted_header + payload + hash

    @staticmethod
    def register_success(dest_phone_id):
        """
        This method constructs a REGISTER_SUCCESS response with the given destination phone ID.

        Args:
            dest_phone_id (str): The destination phone id.

        Returns:
            Response: A Response object indicating a successful registration with an empty payload.
        """
        # No payload for REGISTER_SUCCESS
        return Response(dest_phone_id, ResponseCode.REGISTER_SUCCESS, EmptyPayload())

    @staticmethod
    def reconnect_success(dest_phone_id):
        """
        Creates a Response object indicating a successful reconnection.

        Args:
            dest_phone_id (bytes): The destination phone id.

        Returns:
            Response: A Response object indicating a successful reconnection with an empty payload.
        """
        # No payload for RECONNECT_SUCCESS
        return Response(dest_phone_id, ResponseCode.RECONNECT_SUCCESS, EmptyPayload())

    @staticmethod
    def share_public_keys(dest_phone_id, public_keys_list):
        """
        Creates a Response object containing an encrypted list of public keys.

        Args:
            dest_phone_id (bytes): The the destination phone id of the user we are going to share the public keys with.
            public_keys_list (str): An encoded list of public keys to be shared (will be encrypted using the AES key that is created inside this method).
                                    The list has to be a string in the following format "phone_id:HEX_ENCODED_RSA_PUB_KEY, phone_ID:HEX_ENCODED_RSA_PUB_KEY, ..."

        Returns:
            Response object

        """
        aes_key = CryptoHelper.generate_AES_key()
        aes_iv = CryptoHelper.generate_iv()
        encrypted_pub_keys = CryptoHelper.encrypt_with_AES_key(
            aes_key, aes_iv, public_keys_list)
        return Response(dest_phone_id, ResponseCode.SHARE_PUBLIC_KEYS, payload=EncryptedPublicKeysPayload(aes_key, aes_iv, encrypted_pub_keys))

    @staticmethod
    def message_transfer_success(dest_phone_id):
        """
        Create a response indicating successful message transfer.

        Args:
            dest_phone_id (bytes): The destination phone id.

        Returns:
            A response object with a MESSAGE_TRANSFER_SUCCESS code and an empty payload.
        """
        # No payload for MESSAGE_TRANSFER_SUCCESS
        return Response(dest_phone_id, ResponseCode.MESSAGE_TRANSFER_SUCCESS, EmptyPayload())

    @staticmethod
    def end_user_offline(dest_phone_id):
        """
        Create a response for notifying that the end user is offline.

        Args:
            dest_phone_id (bytes): The destination phone id.

        Returns:
            A response object indicating the end user is offline.
        """
        # No payload for END_USER_OFFLINE
        return Response(dest_phone_id, ResponseCode.END_USER_OFFLINE, EmptyPayload())
