import socket
import threading
import random
import string
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def random_alphanumeric_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_message(message, aes_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext


def decrypt_message(encrypted_message, aes_key):
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_data) + unpadder.finalize()


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("192.168.1.2", 9999))
    server.listen()
    client, addr = server.accept()
    return client


def send_messages(sock, keys):
    pr1, prs1, pr2, prs2, pr3, prs3 = keys
    while True:
        message = input("You: ")
        encrypted_message = encrypt_message(message, aes_key)
        sock.send(encrypted_message)


def get_messages(sock, keys):
    pr1, prs1, pr2, prs2, pr3, prs3 = keys
    try:
        while True:
            encrypted_message = sock.recv(4096)
            if not encrypted_message:
                print("Connection with the partner closed.")
                break
            decrypted_message = decrypt_message(encrypted_message, aes_key)
            print("Partner: " + decrypted_message)

    except ConnectionResetError:
        print("Connection with the partner closed.")


def main():
    private_key_user1, public_key_user1 = generate_keys()
    private_key_user2, public_key_user2 = generate_keys()

    # Exchange public keys (ECDSA key exchange)
    public_key_user1_bytes = public_key_user1.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_user2_bytes = public_key_user2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Send public keys to the other user
    # Example: user1 sends its public key to user2
    # user2 sends its public key to user1

    # Convert received bytes to public key objects
    # Example: user1 receives user2's public key and vice versa

    # User1's shared keys
    shared_key_1_2 = private_key_user1.exchange(ec.ECDH(), public_key_user2)
    shared_key_1_3 = private_key_user1.exchange(ec.ECDH(), public_key_user3)

    # User2's shared keys
    shared_key_2_1 = private_key_user2.exchange(ec.ECDH(), public_key_user1)
    shared_key_2_3 = private_key_user2.exchange(ec.ECDH(), public_key_user3)

    # Generate AES keys using the shared keys
    salt = os.urandom(16)
    password_1_2 = derive_key_from_password(shared_key_1_2, salt)
    password_1_3 = derive_key_from_password(shared_key_1_3, salt)
    password_2_1 = derive_key_from_password(shared_key_2_1, salt)
    password_2_3 = derive_key_from_password(shared_key_2_3, salt)
    password_3_1 = derive_key_from_password(shared_key_3_1, salt)
    password_3_2 = derive_key_from_password(shared_key_3_2, salt)

    aes_key_1_2 = password_1_2[:32]
    aes_key_1_3 = password_1_3[:32]
    aes_key_2_1 = password_2_1[:32]
    aes_key_2_3 = password_2_3[:32]
    aes_key_3_1 = password_3_1[:32]
    aes_key_3_2 = password_3_2[:32]

    # User1's keys
    keys_user1 = (aes_key_1_2, aes_key_1_3)

    # User2's keys
    keys_user2 = (aes_key_2_1, aes_key_2_3)

    # User3's keys
    keys_user3 = (aes_key_3_1, aes_key_3_2)

    choice = input("Host (1) or connect (2): ")

    if choice == "1":
        client = start_server()

    elif choice == "2":
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("192.168.1.2", 9999))

    else:
        exit()

    print(random_alphanumeric_string(77))

    receive_thread = threading.Thread(
        target=get_messages, args=(client, keys_user2))
    receive_thread.daemon = True
    receive_thread.start()

    send_thread = threading.Thread(
        target=send_messages, args=(client, keys_user1))
    send_thread.start()

    try:
        send_thread.join()
    except KeyboardInterrupt:
        print("Chat ended.")


if __name__ == "__main__":
    main()
