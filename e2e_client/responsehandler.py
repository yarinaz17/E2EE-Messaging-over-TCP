from response import *
from connection import Connection
from cryptohelper import CryptoHelper
import shared_vars


class ResponseHandler:

    @staticmethod
    def handle_response(res: Response, conn: Connection):
        """
        This method receives a response and a Connection object from which the response was originated from.
        Then it verifies the hash and invokes the appropriate response handler according to the received response.
        Returns True if the response was successfully handled, False otherwise.
        """
        # Server closed the connection (empty response returned)
        if res is None:
            print(
                "\n[CRITICAL] The server has closed connection due to security reasons. exiting...")
            conn.close()
            return False

        # Check hash
        computed_hash_obj = CryptoHelper.compute_SHA256(
            res.get_header_bytes(), res.get_payload().get_bytes())

        response_hash = res.get_hash()
        phone_id = res.get_phone_id().decode()
        if res.get_code() == ResponseCode.SEND_MESSAGE.value:
            sender_pub_key = conn.get_public_key_from_keys_dict(
                phone_id)
            if not CryptoHelper.verify_signature(computed_hash_obj, sender_pub_key, response_hash):
                print(
                    "\n[CRITICAL] Hash mismatch. exiting...")
                conn.close()
                return False
        else:
            if not CryptoHelper.verify_signature(computed_hash_obj, conn.server_public_key, response_hash):
                print(
                    "\n[CRITICAL] Hash mismatch. exiting...")
                conn.close()
                return False

        response_code = res.get_code()

        if response_code == ResponseCode.REGISTER_SUCCESS.value:
            print_server_message(
                "[INFO] Successful registration")
        elif response_code == ResponseCode.RECONNECT_SUCCESS.value:
            print_server_message(
                "[INFO] Successful reconnection")
        elif response_code == ResponseCode.MESSAGE_TRANSFER_SUCCESS.value:
            print_server_message(
                "[INFO] Message sent successfully")
        elif response_code == ResponseCode.END_USER_OFFLINE.value:
            print_server_message(
                "[INFO] Recipient is offline and will receive his message upon reconnect")
        elif response_code == ResponseCode.SHARE_PUBLIC_KEYS.value:
            print_server_message(
                "[INFO] Received public keys of users from server")
            # Decrypt the public keys list using the AES symmetric key
            aes_key = res.get_payload().get_aes_key()
            aes_iv = res.get_payload().get_aes_iv()
            encrypted_pub_key = res.get_payload().get_encrypted_pub_key()
            all_users_pub_keys = CryptoHelper.decrypt_with_AES(
                aes_key, aes_iv, encrypted_pub_key)
            # Parse and store the public keys inside the connection object
            conn.set_keys_dict(all_users_pub_keys.decode())
        elif response_code == ResponseCode.SEND_MESSAGE.value:
            # Obtain AES key, IV and the encrypted message
            aes_key = res.get_payload().get_aes_key()
            aes_iv = res.get_payload().get_aes_iv()
            encrypted_msg = res.get_payload().get_encrypted_message()
            # Decrypt the message using the AES key and the IV (Initialization vector)
            message = CryptoHelper.decrypt_with_AES(
                aes_key, aes_iv, encrypted_msg)
            print_server_message(
                f"[MESSAGE] From {phone_id} : {message.decode()}")
        return True


def print_server_message(message):
    """
    Print the server message and re-render the input prompt.

    Parameters:
    message (str): The message to be printed from the server.
    """
    print(f"\r{message}")
    if shared_vars.is_session_established:
        print("Enter message: ", end='', flush=True)
    else:
        print("Enter destination phone id: ", end='', flush=True)
