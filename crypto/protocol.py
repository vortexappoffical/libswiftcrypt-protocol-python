import os
import hashlib
import hmac
import base64
import sqlite3
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS

# Key derivation function using SHA-256
def derive_key(password, salt, iterations=100000):
    return PBKDF2(password, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)

# RSA key generation
def generate_rsa_keypair():
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# ECDH key exchange
def generate_ecdh_keypair():
    key = ECC.generate(curve='P-256')
    private_key = key.export_key(format='PEM')
    public_key = key.public_key().export_key(format='PEM')
    return private_key, public_key

def derive_shared_key(private_key_pem, peer_public_key_pem):
    private_key = ECC.import_key(private_key_pem)
    peer_public_key = ECC.import_key(peer_public_key_pem)
    shared_key = private_key.d * peer_public_key.pointQ
    return int.to_bytes(shared_key.x, length=32, byteorder='big')

# AES encryption (AES-256-CBC)
def aes_encrypt_cbc(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(data))
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def aes_decrypt_cbc(key, data):
    data = base64.b64decode(data)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext))

# AES encryption (AES-256-CTR)
def aes_encrypt_ctr(key, data):
    cipher = AES.new(key, AES.MODE_CTR)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(data)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def aes_decrypt_ctr(key, data):
    data = base64.b64decode(data)
    nonce = data[:8]
    ciphertext = data[8:]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)

# Padding for AES (PKCS7)
def pad(data):
    length = 16 - (len(data) % 16)
    return data + bytes([length]) * length

def unpad(data):
    return data[:-data[-1]]

# Message signing
def sign_message(private_key_pem, message):
    private_key = RSA.import_key(private_key_pem)
    h = SHA256.new(message)
    signature = pkcs1_15.new(private_key).sign(h)
    return base64.b64encode(signature).decode('utf-8')

def verify_message(public_key_pem, message, signature):
    public_key = RSA.import_key(public_key_pem)
    h = SHA256.new(message)
    signature = base64.b64decode(signature)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Message authentication code (HMAC)
def generate_mac(key, message):
    return hmac.new(key, message, hashlib.sha256).hexdigest()

def verify_mac(key, message, mac):
    return hmac.compare_digest(mac, generate_mac(key, message))

# Replay attack protection (using message ID and timestamp)
def generate_message_id():
    return base64.b64encode(get_random_bytes(16)).decode('utf-8')

def store_message_id(message_id, timestamp):
    conn = sqlite3.connect('message_ids.db')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS message_ids (id TEXT PRIMARY KEY, timestamp INTEGER)")
    cursor.execute("INSERT INTO message_ids (id, timestamp) VALUES (?, ?)", (message_id, timestamp))
    conn.commit()
    conn.close()

def check_message_id(message_id):
    conn = sqlite3.connect('message_ids.db')
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM message_ids WHERE id = ?", (message_id,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists
