import threading
from request import Request, Op
from response import *
from client import Client
from connection import Connection
from clients_list import clients_list
from Crypto.PublicKey import RSA

"""This RequestHandler class is used to handle the different requests supported by the protocol"""


class RequestHandler:
    def __init__(self):
        pass

    def handle_request(self, originating_connection: Connection, request: Request):
        """
        Handles incoming requests by invoking the appropriate handler based on the request code.

        Args:
            originating_connection (Connection): The connection from which the request originated.
            request (Request): The request object containing the details of the request.

        Returns:
            The result of the invoked request handler, or None if the request is invalid or cannot be processed.

        Request Handling:
            - Verifies the request hash for all request types except "SEND_MESSAGE".
            - For "REGISTER" requests, it verifies the hash using the public key received in the request payload.
            - For other requests, retrieves the appropriate client's public key from the global clients list then verifies the hash.
            - Invokes the appropriate handler based on the request code:
                - Op.REGISTER: Handles registration requests.
                - Op.RECONNECT: Handles reconnect requests.
                - Op.GET_PUBLIC_KEYS: Handles public keys requests.
                - Op.SEND_MESSAGE: Handles message sending requests.

        Returns:
            The result of the specific request handler or None if the request is invalid.
        """

        code = Op(request.get_code())

        # Check hash for every type of request other than "SEND_MESSAGE" (if it's "SEND_MESSAGE", then the receiving client will check its hash)
        if code != Op.SEND_MESSAGE:
            # Op.REGISTER is a special case, since this is the first time we obtain the public key from the user
            # In this case, we will use the public key received from the user inside the payload field of the request
            if code == Op.REGISTER:
                pub_key = RSA.importKey(request.get_payload().get_public_key())
            else:
                # Obtain client's public key
                client = next((c for c in clients_list if c.get_phone_id()
                               == request.get_phone_id()), None)
                if client:
                    pub_key = client.get_public_key()
                else:
                    pub_key = None

            # ------------------- Calculate hash and compare ---------------------------
            computed_hash_obj = CryptoHelper.compute_SHA256(
                request.get_header_bytes(), request.get_payload().get_bytes())

            if not (pub_key and CryptoHelper.verify_signature(computed_hash_obj, pub_key, request.get_hash())):
                return None
        if code == Op.REGISTER:
            print("[SERVER] Incoming registration request from peer.")
            res = self.handle_register(originating_connection, request)
            if res == None:
                print(
                    "[SERVER] Peer is already registered, refusing registration request.")
            return res
        if code == Op.RECONNECT:
            print("[SERVER] Incoming reconnect request from peer")
            res = self.handle_reconnect(originating_connection, request)
            if res == None:
                print(
                    "[SERVER] Peer is not registered, refusing reconnect request.")
            return res
        if code == Op.GET_PUBLIC_KEYS:
            print("[SERVER] Incoming public key request from peer")
            return self.handle_public_keys_request(request)
        if code == Op.SEND_MESSAGE:
            print(
                f"[SERVER] Incoming message from peer (message will be routed to {request.get_dest_phone_id().decode()})")
            return self.handle_message(request)

        # Return None in case of a bad request
        return None

    def handle_register(self, originating_connection: Connection, request: Request):
        """
        Handles a registration request from a client.

        This method checks if the client is already registered by comparing the phone id
        from the request with the phone ids of the clients in the clients_list. If the client
        is not already registered, it creates a new Client object, sets its phone id and public key obtained from the request,
        and appends it to the clients_list. It also updates the originating connection with the
        client's public key and starts a new thread to update all the online clients about the new registration (sharing the newly registered user public key).

        Args:
            originating_connection (Connection): The connection object from which the request originated.
            request (Request): The registration request containing the client's phone id and public key.

        Returns:
            Response: A success response if the registration is successful, otherwise None.
        """
        """This method receives a registration request and registers the client by creating new client object in memory and appending it to the list of clients"""
        # check if user is already registered, if not, register
        if request.get_phone_id() in [c.get_phone_id() for c in clients_list]:
            return None

        new_client = Client(originating_connection)
        new_client.set_phone_id(request.get_phone_id())
        new_client.set_public_key(request.get_payload().get_public_key())
        originating_connection.set_endpoint_public_key(
            new_client.get_public_key())
        clients_list.append(new_client)
        # Update all online clients about the newly added public key / client
        threading.Thread(target=self.share_public_keys,
                         args=(request.get_phone_id(),)).start()
        return Response.register_success(request.get_phone_id())

    def handle_reconnect(self, originating_connection: Connection, request: Request):
        """
        Handles the reconnection of a client.

        This method searches for an existing client in the clients_list using the phone id from the request.
        If the client is found, it sets the endpoint public key on the originating connection to the public key of the reconnecting client.
        Then it updates the client's connection object with the originating connection object, so all further communications with that client will be done
        through this Connection object (which also contains the TCP socket)
        If the client has pending messages, it launches a separate thread to send those messages.

        Args:
            originating_connection (Connection): The connection object that initiated the reconnection request.
            request (Request): The request object containing the phone ID of the client attempting to reconnect.

        Returns:
            Response: A success response if the client is found and reconnected.
            None: If no client is found with the given phone id.
        """
        client = next((c for c in clients_list if c.get_phone_id()
                       == request.get_phone_id()), None)

        if client:
            # update client's Connection object
            # so from now and on all messages and responses to this client will be forwarded through this Connection object
            originating_connection.set_endpoint_public_key(
                client.get_public_key())
            client.set_connection(originating_connection)
            # Check for pending messages, if there are some - Launch a seperate thread to send the pending messages
            if client.pending_messages_count() > 0:
                threading.Thread(target=client.send_pending_messages).start()

            return Response.reconnect_success(request.get_phone_id())
        else:
            return None

    def handle_public_keys_request(self, request: Request):
        """
        Handles the request to share public keys of all users.

        This method processes a request to retrieve the public keys of all users in the system.
        It concatenates the phone id and public key of each client in the `clients_list` into a single string,
        encoded in DER format and represented in hexadecimal.

        Args:
            request (Request): The request object containing the phone id of the requester.

        Returns:
            Response: A response object containing the concatenated public keys of all users if there are any users in the list.
        """
        all_users_keys = ",".join(
            f"{client.get_phone_id().decode()}:{client.get_public_key().export_key(format='DER').hex()}" for client in clients_list).encode()

        if len(clients_list) > 0:
            return Response.share_public_keys(request.phone_id, all_users_keys)

    def share_public_keys(self, phone_id):
        """
        Shares the public keys of all users with all online clients except the newly added client.

        Args:
            phone_id (bytes): The phone id of the newly added client.

        The function collects the public keys of all users, formats them as a comma-separated string,
        and sends this information to all online clients except the one identified by `phone_id`.
        """
        all_users_keys = ",".join(
            f"{client.get_phone_id().decode()}:{client.get_public_key().export_key(format='DER').hex()}" for client in clients_list).encode()

        # Update all online clients except the newly added client:
        for c in clients_list:
            if c.is_online() and c.get_phone_id() != phone_id:
                res = Response.share_public_keys(
                    c.get_phone_id(), all_users_keys)
                c.send_response(res)

    def handle_message(self, request: Request):
        """
        Handles an incoming message request and forwards it to the recipient.

        Args:
            request (Request): The incoming message request.

        Returns:
            Response: A response indicating the result of the message handling.
                - If the destination user does not exist, returns None.
                - If the message is successfully forwarded to an online user, returns a success response.
                - If the user is offline, adds the message to the user's pending messages and returns an offline response.
        """

        # Obtain the number of the destination user
        dest_phone_id = request.get_dest_phone_id()
        # Look for that end user in the clients list
        end_user = next((c for c in clients_list if c.get_phone_id()
                         == dest_phone_id), None)

        # If user doesn't exist signal bad request (by returning None)
        if not end_user:
            return None
        # Check if user is online
        if end_user.is_online():
            # Forward message to recipient, if successful, return success response
            if (end_user.forward_message(request)):
                return Response.message_transfer_success(request.get_phone_id())
        else:
            # User is offline, add message to pending and return user is offline response
            end_user.add_pending_message(request)

        return Response.end_user_offline(request.get_phone_id())
