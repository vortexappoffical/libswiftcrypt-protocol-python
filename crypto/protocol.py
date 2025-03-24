import hashlib
import hmac
import os
import socket
import threading
import time
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Constants
AES_KEY_SIZE = 32  # AES-256
AES_BLOCK_SIZE = 16
RSA_KEY_SIZE = 4096
ECDH_KEY_SIZE = 256
HMAC_SIZE = 32
SALT_SIZE = 16
ITERATIONS = 100000

# Helper functions
def generate_salt():
    return os.urandom(SALT_SIZE)

def kdf(password, salt):
    return PBKDF2(password, salt, dkLen=AES_KEY_SIZE, count=ITERATIONS, hmac_hash_module=SHA256)

def generate_rsa_keypair():
    key = RSA.generate(RSA_KEY_SIZE)
    return key, key.publickey()

def encrypt_rsa(public_key, data):
    return public_key.encrypt(data, None)[0]

def decrypt_rsa(private_key, encrypted_data):
    return private_key.decrypt(encrypted_data)

def sign_rsa(private_key, data):
    hasher = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(hasher)
    return signature

def verify_rsa(public_key, data, signature):
    hasher = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(hasher, signature)
        return True
    except (ValueError, TypeError):
        return False

def encrypt_aes(key, data):
    iv = get_random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data, AES_BLOCK_SIZE))
    return iv + encrypted_data

def decrypt_aes(key, encrypted_data):
    iv = encrypted_data[:AES_BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[AES_BLOCK_SIZE:]), AES_BLOCK_SIZE)
    return decrypted_data

def create_hmac(key, data):
    return HMAC.new(key, data, SHA256).digest()

def verify_hmac(key, data, hmac_to_verify):
    hmac_calculated = HMAC.new(key, data, SHA256).digest()
    return hmac.compare_digest(hmac_calculated, hmac_to_verify)

def generate_ecdh_keys():
    return os.urandom(ECDH_KEY_SIZE), os.urandom(ECDH_KEY_SIZE)

def perform_ecdh_exchange(private_key, peer_public_key):
    shared_secret = hashlib.sha256(private_key + peer_public_key).digest()
    return shared_secret

# Chat encryption protocol
class SecureChatProtocol:
    def __init__(self):
        self.rsa_private_key, self.rsa_public_key = generate_rsa_keypair()
        self.aes_key = None
        self.hmac_key = None
        self.ecdh_private_key, self.ecdh_public_key = generate_ecdh_keys()

    def establish_secure_connection(self, peer_public_key):
        shared_secret = perform_ecdh_exchange(self.ecdh_private_key, peer_public_key)
        self.aes_key = kdf(shared_secret, generate_salt())
        self.hmac_key = kdf(shared_secret, generate_salt())

    def encrypt_message(self, message):
        encrypted_message = encrypt_aes(self.aes_key, message.encode())
        message_hmac = create_hmac(self.hmac_key, encrypted_message)
        return encrypted_message + message_hmac

    def decrypt_message(self, encrypted_message):
        message_hmac = encrypted_message[-HMAC_SIZE:]
        encrypted_message = encrypted_message[:-HMAC_SIZE]
        if not verify_hmac(self.hmac_key, encrypted_message, message_hmac):
            raise ValueError("Message authentication failed")
        return decrypt_aes(self.aes_key, encrypted_message).decode()

    def sign_message(self, message):
        return sign_rsa(self.rsa_private_key, message.encode())

    def verify_message_signature(self, message, signature, peer_public_key):
        return verify_rsa(peer_public_key, message.encode(), signature)
