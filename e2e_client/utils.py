from Crypto.PublicKey import RSA
from connection import Connection
from client import *
import os
import shared_vars


def mock_receive_OTP_by_secure_channel():
    input("Enter OTP: ")


def mock_send_OTP_by_secure_channel():
    print("OTP sent via secure channel")
    # Mocking the OTP sent by the server
    print("Successful validation!")


def init_client() -> Client:
    """
    Initializes and returns a Client object.

    This function performs the following steps:
    1. Reads the server's public key.
    2. Checks if the client's private key, public key, and phone ID already exist.
       - If they exist, sets the need_to_register flag to False and reads the phone ID and client's private key.
       - If they do not exist, generates new keys (and saves them in the current working directory), prompts the user to enter a phone ID, performs mock OTP (One-Time Password) 
         operations, reads the newly created client's private key, and writes the phone ID to a file.
    3. Creates a Connection object using the server's public key and the client's private key.
    4. Creates and returns a Client object with the phone ID, server's public key, client's public key, client's private key, 
       and the Connection object.

    Returns:
        Client: The initialized Client object.

    Raises:
        Exception: If any error occurs during the initialization process, it prints the error message.
    """
    try:
        servers_pub_key = read_servers_public_key()
        if os.path.exists("client_private.pem") and os.path.exists("client_public.pem") and os.path.exists("phone_id.txt"):
            shared_vars.need_to_register = False
            print("[INFO] Keys and phone_id already exist, performing reconnection...")
            phone_id = read_phone_id()
            priv_key = read_clients_private_key()
            # Save key in DER format (to obtain shorter encoding, since we need to encrypt this key later on with the server's public key)
            pub_key = priv_key.publickey().export_key('DER')
        else:
            print(
                "[INFO] Keys and phone_id do not exist, generating keys and performing registration...")
            generate_keys()
            phone_id = input("Enter phone id: ")
            mock_receive_OTP_by_secure_channel()
            mock_send_OTP_by_secure_channel()
            priv_key = read_clients_private_key()
            # Save key in DER format (to obtain shorter encoding, since we need to encrypt this key later on with the server's public key)
            pub_key = priv_key.publickey().export_key('DER')
            write_phone_id(phone_id)

        conn = Connection('127.0.0.1', 5555, servers_pub_key, priv_key)
        client = Client(phone_id, servers_pub_key, pub_key, priv_key, conn)
        return client

    except Exception as ex:
        print(f"An error occurred: {ex}")


def generate_keys():
    # Generate public and private keys then save them
    key = RSA.generate(1024)
    private_key = key.export_key()
    with open('client_private.pem', 'wb') as f:
        f.write(private_key)
    public_key = key.publickey().export_key()
    with open('client_public.pem', 'wb') as f:
        f.write(public_key)


def delete_keys():
    # Delete public and private keys
    if os.path.exists("client_private.pem"):
        os.remove("client_private.pem")
    if os.path.exists("client_public.pem"):
        os.remove("client_public.pem")


def write_phone_id(phone_id):
    # Write phone_id to file
    with open('phone_id.txt', 'w') as f:
        f.write(phone_id)


def read_phone_id():
    # Load phone_id from file
    with open('phone_id.txt', 'r') as f:
        return f.read().strip()


def read_servers_public_key():
    # Load server's public key from file
    with open('server_public.pem', 'rb') as f:
        return RSA.import_key(f.read())


def read_clients_private_key():
    # Load client's private key from file
    with open('client_private.pem', 'rb') as f:
        return RSA.import_key(f.read())


def read_clients_public_key():
    # Load client's public key from file
    with open('client_public.pem', 'rb') as f:
        return RSA.import_key(f.read())
