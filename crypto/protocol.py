from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import DSS
from Crypto.Hash import SHA256, HMAC
import os
import socket
import base64

# Key derivation function
def derive_key(password, salt):
    return scrypt(password, salt, key_len=32, N=2**20, r=8, p=1)

# RSA key generation
def generate_rsa_keypair():
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# ECC key generation
def generate_ecc_keypair():
    key = ECC.generate(curve='P-256')
    private_key = key.export_key(format='DER')
    public_key = key.public_key().export_key(format='DER')
    return private_key, public_key

# AES encryption
def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

# AES decryption
def aes_decrypt(key, iv, ct):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

# Message signing
def sign_message(private_key, message):
    h = SHA256.new(message.encode())
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(h)
    return base64.b64encode(signature).decode('utf-8')

# Message verification
def verify_message(public_key, message, signature):
    h = SHA256.new(message.encode())
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(h, base64.b64decode(signature))
        return True
    except ValueError:
        return False

# Generate HMAC
def generate_hmac(key, message):
    h = HMAC.new(key, digestmod=SHA256)
    h.update(message.encode())
    return h.hexdigest()

# Verify HMAC
def verify_hmac(key, message, hmac_value):
    h = HMAC.new(key, digestmod=SHA256)
    h.update(message.encode())
    try:
        h.hexverify(hmac_value)
        return True
    except ValueError:
        return False

# ECDH key exchange
def ecdh_key_exchange(private_key, peer_public_key):
    private_key = ECC.import_key(private_key)
    peer_public_key = ECC.import_key(peer_public_key)
    shared_secret = private_key.pointQ * peer_public_key.pointQ
    return SHA256.new(shared_secret.export_key(format='DER')).digest()

# Padding for AES
def pad(data, block_size):
    padding = block_size - len(data) % block_size
    return data + (chr(padding) * padding).encode()

# Unpadding for AES
def unpad(data, block_size):
    padding = data[-1]
    return data[:-padding]
