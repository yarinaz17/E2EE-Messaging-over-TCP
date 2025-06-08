from client import *
from utils import *
from responsehandler import ResponseHandler
import threading
import shared_vars


def wait_for_responses(client: Client):
    """
    Continuously reads and handles responses from the given client as long as the connection is open.

    Args:
        client (Client): The client instance from which to read responses.

    Side Effects:
        Sets `shared_vars.is_connection_open` to False when the connection is closed.
    """
    while ResponseHandler.handle_response(client.read_response(), client.conn):
        pass
    shared_vars.is_connection_open = False


def main():
    # Initialize a client object (create RSA key-pair if needed or use an existent key-pair)
    client = init_client()
    # Check if connection with server can be established
    if client.open_connection():
        # Dispatch the response handling to a separate thread (in case that the client was successfully initialized and is connected to the server)
        response_thread = threading.Thread(
            target=wait_for_responses, args=(client,))
        response_thread.start()
        if shared_vars.need_to_register:
            client.register()
        else:
            client.reconnect()

        # Start a messaging session
        client.start_messaging()
        # Wait for the response handling thread
        response_thread.join()


if __name__ == "__main__":
    main()
