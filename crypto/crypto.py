import os
import time
import struct
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hmac
import zlib

# Constants
AES_KEY_SIZE = 32  # 256-bit
HMAC_KEY_SIZE = 32
NONCE_SIZE = 12
RSA_KEY_SIZE = 4096
TIMESTAMP_TOLERANCE = 30  # Seconds for replay attack protection

class main:
    def __init__(self):
        """Initialize E2EE with ECDH key exchange and RSA encryption."""
        # Long-term keys
        self.rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
        self.rsa_public_key = self.rsa_private_key.public_key()

        # Ephemeral keys for each session (to ensure Forward Secrecy)
        self.ephemeral_ecdh_private_key = None
        self.ephemeral_ecdh_public_key = None
        self.shared_secret = None
        self.aes_key = None
        self.hmac_key = None

    def generate_ephemeral_keys(self):
        """Generate ephemeral ECDH keys for each session."""
        self.ephemeral_ecdh_private_key = ec.generate_private_key(ec.SECP384R1())  # New ephemeral key pair
        self.ephemeral_ecdh_public_key = self.ephemeral_ecdh_private_key.public_key()

    def get_ephemeral_ecdh_public_key(self):
        """Export ephemeral ECDH public key."""
        if self.ephemeral_ecdh_public_key:
            return self.ephemeral_ecdh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        return None

    def derive_shared_secret(self, peer_public_key_pem):
        """Derive shared secret using ephemeral ECDH."""
        # Generate a new ephemeral key pair for each session to ensure Forward Secrecy
        self.generate_ephemeral_keys()

        peer_public_key = serialization.load_pem_public_key(peer_public_key_pem)
        shared_secret = self.ephemeral_ecdh_private_key.exchange(ec.ECDH(), peer_public_key)

        # Use HKDF to derive AES and HMAC keys
        kdf = HKDF(algorithm=hashes.SHA256(), length=AES_KEY_SIZE + HMAC_KEY_SIZE, salt=None, info=b'E2EE Key Derivation')
        key_material = kdf.derive(shared_secret)

        self.aes_key = key_material[:AES_KEY_SIZE]
        self.hmac_key = key_material[AES_KEY_SIZE:]

        return self.aes_key  # Return the AES key directly

    def sign_message(self, message):
        """Sign the message using RSA to provide authenticity."""
        signature = self.rsa_private_key.sign(
            message.encode(),
            padding.PSS(mgf=padding.MGF1(algorithm=hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature  # Return the raw signature

    def verify_signature(self, message, signature):
        """Verify the signature of a message using RSA."""
        try:
            self.rsa_public_key.verify(
                signature,
                message.encode(),
                padding.PSS(mgf=padding.MGF1(algorithm=hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def encrypt(self, plaintext):
        """Encrypts data using AES-256-GCM with integrity protection and compression."""
        # Compress the plaintext before encryption
        compressed_data = zlib.compress(plaintext.encode())

        nonce = os.urandom(NONCE_SIZE)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(compressed_data) + encryptor.finalize()

        # Create HMAC for integrity
        mac = hmac.new(self.hmac_key, ciphertext, hashlib.sha256).digest()

        # Include timestamp for replay protection
        timestamp = struct.pack(">Q", int(time.time()))

        # Return the encrypted data as raw bytes
        return nonce + encryptor.tag + timestamp + mac + ciphertext

    def decrypt(self, encrypted_data):
        """Decrypts data, decompress and verifies integrity & freshness."""
        nonce = encrypted_data[:NONCE_SIZE]
        tag = encrypted_data[NONCE_SIZE:NONCE_SIZE+16]
        timestamp = struct.unpack(">Q", encrypted_data[NONCE_SIZE+16:NONCE_SIZE+24])[0]
        mac = encrypted_data[NONCE_SIZE+24:NONCE_SIZE+56]
        ciphertext = encrypted_data[NONCE_SIZE+56:]

        # Replay protection: check timestamp
        if abs(time.time() - timestamp) > TIMESTAMP_TOLERANCE:
            raise Exception("Replay attack detected!")

        # Verify HMAC
        expected_mac = hmac.new(self.hmac_key, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise Exception("Data integrity compromised!")

        # Decrypt
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Decompress the data after decryption
        return zlib.decompress(decrypted_data).decode()

    def encrypt_symmetric_key(self):
        """Encrypt AES key with RSA-4096."""
        encrypted_key = self.rsa_public_key.encrypt(
            self.aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return encrypted_key  # Return the encrypted key as raw bytes

    def decrypt_symmetric_key(self, encrypted_key):
        """Decrypt AES key using RSA-4096."""
        decrypted_key = self.rsa_private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        self.aes_key = decrypted_key
        return self.aes_key  # Return the decrypted key directly

    def encrypt_metadata(self, metadata):
        """Encrypts metadata (IP, port, etc.)."""
        metadata_json = json.dumps(metadata).encode()
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(os.urandom(NONCE_SIZE)))
        encryptor = cipher.encryptor()
        encrypted_metadata = encryptor.update(metadata_json) + encryptor.finalize()
        return encrypted_metadata  # Return the encrypted metadata as raw bytes

    def decrypt_metadata(self, encrypted_metadata):
        """Decrypts metadata."""
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(os.urandom(NONCE_SIZE)))
        decryptor = cipher.decryptor()
        return json.loads(decryptor.update(encrypted_metadata) + decryptor.finalize())
    
    def handshake(self, peer_public_key_pem):
        """Optimized handshake with Forward Secrecy."""
        # Generate ephemeral keys for this session
        ephemeral_public_key = self.get_ephemeral_ecdh_public_key()

        # Derive shared secret using ephemeral ECDH key pair
        shared_secret = self.derive_shared_secret(peer_public_key_pem)

        # Cache the shared secret for future use to avoid recalculating for each message
        self.shared_secret = shared_secret

        # Return ephemeral public key and the shared secret for RSA encryption of symmetric key
        return {
            "shared_secret": shared_secret,
            "ephemeral_public_key": ephemeral_public_key,
            "public_key": self.get_rsa_public_key(),
        }

    def secure_message_exchange(self, peer_public_key_pem, message):
        """Exchange a secure message (sign, encrypt, decrypt) with Forward Secrecy."""
        # Handshake to derive shared secret and public keys
        handshake_data = self.handshake(peer_public_key_pem)
        
        # Sign the message before encrypting
        signed_message = self.sign_message(message)
        
        # Encrypt the message
        encrypted_message = self.encrypt(message)
        
        return {
            "signed_message": signed_message,
            "encrypted_message": encrypted_message,
            "handshake_data": handshake_data
        }

    def authenticate_peer(self, peer_public_key_pem, signed_message):
        """Authenticate the peer by verifying their signed message."""
        if self.verify_signature(signed_message, peer_public_key_pem):
            return True
        return False

    def encrypt_file(self, file_path, output_file_path):
        """Encrypt a file using AES-256-GCM, integrity protection, and compression."""
        with open(file_path, 'rb') as f:
            # Read the entire file and compress it
            file_data = f.read()
            compressed_data = zlib.compress(file_data)

        nonce = os.urandom(NONCE_SIZE)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(compressed_data) + encryptor.finalize()

        # Create HMAC for integrity
        mac = hmac.new(self.hmac_key, ciphertext, hashlib.sha256).digest()

        # Include timestamp for replay protection
        timestamp = struct.pack(">Q", int(time.time()))

        # Write the encrypted data to the output file
        with open(output_file_path, 'wb') as out_file:
            out_file.write(nonce + encryptor.tag + timestamp + mac + ciphertext)

    def decrypt_file(self, encrypted_file_path, output_file_path):
        """Decrypt an encrypted file, decompress it, and verify integrity."""
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()

        nonce = encrypted_data[:NONCE_SIZE]
        tag = encrypted_data[NONCE_SIZE:NONCE_SIZE+16]
        timestamp = struct.unpack(">Q", encrypted_data[NONCE_SIZE+16:NONCE_SIZE+24])[0]
        mac = encrypted_data[NONCE_SIZE+24:NONCE_SIZE+56]
        ciphertext = encrypted_data[NONCE_SIZE+56:]

        # Replay protection: check timestamp
        if abs(time.time() - timestamp) > TIMESTAMP_TOLERANCE:
            raise Exception("Replay attack detected!")

        # Verify HMAC
        expected_mac = hmac.new(self.hmac_key, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise Exception("Data integrity compromised!")

        # Decrypt
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Decompress the data after decryption
        decompressed_data = zlib.decompress(decrypted_data)

        # Write the decrypted data to the output file
        with open(output_file_path, 'wb') as out_file:
            out_file.write(decompressed_data)
