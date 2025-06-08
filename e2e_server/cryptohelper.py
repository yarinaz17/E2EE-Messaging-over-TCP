from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

AES_KEY_LEN = 16


class CryptoHelper:
    @staticmethod
    def read_private_key():
        with open("private.pem", "rb") as private_key_file:
            return RSA.importKey(private_key_file.read())

    @staticmethod
    def encrypt_with_public_key(data, public_key):
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_data = cipher_rsa.encrypt(data)
        return encrypted_data

    @staticmethod
    def sign_with_private_key(hash, private_key):
        return pkcs1_15.new(private_key).sign(hash)

    @staticmethod
    def verify_signature(hash, public_key, signature):
        try:
            pkcs1_15.new(public_key).verify(hash, signature)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def generate_AES_key():
        return get_random_bytes(AES_KEY_LEN)

    @staticmethod
    def generate_iv():
        return get_random_bytes(AES.block_size)

    @staticmethod
    def encrypt_with_AES_key(key, iv, data):
        data_padded = pad(data, AES.block_size)
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        ct_bytes = cipher_aes.encrypt(data_padded)
        return ct_bytes

    @staticmethod
    def decrypt_with_AES(key, iv, ciphertext):
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        plain = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
        return plain

    @staticmethod
    def decrypt_with_private_key(encrypted_data, private_key):
        cipher_rsa = PKCS1_OAEP.new(private_key)
        data = cipher_rsa.decrypt(encrypted_data)
        return data

    @staticmethod
    def compute_SHA256(header, payload):
        hash_obj = SHA256.new()
        hash_obj.update(header+payload)
        return hash_obj
