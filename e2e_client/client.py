import time
from cryptohelper import CryptoHelper
from connection import Connection
from request import Request, Op, EmptyPayload, PublicKeyPayload, MessagePayload
import shared_vars


class Client:
    def __init__(self, phone_id, servers_pub_key, clients_pub_key, clients_priv_key, conn: Connection):
        self.phone_id = phone_id
        self.servers_pub_key = servers_pub_key
        # public key is needed for registration
        self.clients_pub_key = clients_pub_key
        # private key is needed for decryption of responses / messages
        self.clients_priv_key = clients_priv_key
        self.conn = conn

    def open_connection(self):
        """
        Attempts to open a connection to the server.

        Returns:
            bool: True if the connection was successfully opened, False if the connection was refused.
        """
        try:
            # Open the connection
            self.conn.open()
            return True
        except ConnectionRefusedError:
            print("[ERROR] Couldn't connect to server")
            return False

    def reconnect(self):
        """
        Attempts to reconnect the client by sending a RECONNECT request.

        This method creates a RECONNECT request with the current phone ID and 
        the current timestamp, and sends it using the `_send` method.
        """
        reconnect_request = Request(
            self.phone_id, None, Op.RECONNECT, int(time.time()), EmptyPayload())
        self._send(reconnect_request)

    def register(self):
        """
        Registers the client by sending a registration request to the server.

        This method creates a REGISTER request using the phone ID, 
        current timestamp, and the public key of the registering user, then sends it to the server 
        to register the client.
        """
        register_request = Request(
            self.phone_id, None, Op.REGISTER, int(time.time()), PublicKeyPayload(self.clients_pub_key))
        self._send(register_request)

    def set_end_user(self, dest_phone_id):
        """
        Sets the end user for the current messaging session.

        Args:
            dest_phone_id (str): The destination phone ID to set as the end user.

        Returns:
            True if the end user was successfully set, False otherwise.
        """
        return self.conn.set_end_user(dest_phone_id)

    def get_public_keys(self):
        """
        Retrieves public keys from servers.

        This method constructs a request to obtain all public keys for all available end-users.
        """
        get_end_user_public_key_request = Request(
            self.phone_id, None, Op.GET_PUBLIC_KEYS, int(time.time()), EmptyPayload())
        self._send(get_end_user_public_key_request)

    def send_message(self, dest_phone_id, message):
        """
        Sends an encrypted message to the specified destination phone ID.

        Args:
            dest_phone_id (str): The phone ID of the message recipient.
            message (str): The plaintext message to be sent.
        """

        # Generate AES symmetric key to encrypt the message
        aes_key = CryptoHelper.generate_AES_key()
        iv = CryptoHelper.generate_iv()
        encrypted_message = CryptoHelper.encrypt_with_AES_key(
            aes_key, iv, message.encode())
        # Craft message request
        message_request = Request(self.phone_id, dest_phone_id, Op.SEND_MESSAGE, int(
            time.time()), MessagePayload(aes_key, iv, encrypted_message))
        # Send the request
        self._send(message_request)

    def _send(self, request: Request):
        """
        Sends a request to the server using the established connection.

        Args:
            request (Request): The request object to be sent.

        Side Effects:
            Exits the program with status code 1 if an error occurs while sending the request.
        """
        try:
            self.conn.send_request(request)
        except:
            print("[ERROR] Connection is closed.")
            exit(1)

    def read_response(self):
        """
        Reads the response from the connection.

        Returns:
            The response from the connection if it is open, otherwise None.

        Side Effects:
            Updates shared_vars.is_connection_open to False if the connection is not open or if an error occurs.
            Exits the program with status code 1 if an error occurs while reading the response.
        """
        if not self.conn.is_open():
            shared_vars.is_connection_open = False
            return None
        else:
            try:
                return self.conn.read_response()
            except:
                print("[ERROR] There was a problem with the connection.")
                shared_vars.is_connection_open = False
                exit(1)

    def start_messaging(self):
        """
        Starts a messaging session with the end-user through the server.

        This method performs the following steps:
        1. Obtaining public keys from the server.
        2. Prompts the user to enter the destination phone ID that is then validated according to the public keys that were received from the server.
        3. If destination user does not exist, execution will return to step 2.
        4. Continuously prompts the user to enter messages and sends them to the destination
           as long as the server connection remains open.

        Notes:
            - The method relies on shared variables `shared_vars.is_connection_open` and 
              `shared_vars.is_session_established` to manage the session state.
        """
        # Establish a "messaging session" with the end-user through the server
        end_user_found = False
        # Obtain public keys from server before asking the user to type its destination client
        self.get_public_keys()
        while not end_user_found:
            # Read destination phone number
            dest_phone_id = input("")
            end_user_found = self.set_end_user(dest_phone_id)
            if not end_user_found:
                print("[WARNING] Destination not found...\nEnter destination phone id: ",
                      end='', flush=True)

        # While server hasn't closed the connection, keep sending messages
        while shared_vars.is_connection_open:
            shared_vars.is_session_established = True
            print("Enter message: ", end='', flush=True)
            # Read message from user
            message = input("")
            try:
                if shared_vars.is_connection_open:
                    self.send_message(dest_phone_id, message)
                else:
                    break
            except Exception as ex:
                print(f"An error occurred: {ex}")
                break
