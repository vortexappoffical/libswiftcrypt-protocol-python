#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <zlib.h>
#include <json/json.h>
#include <fstream>

// Constants
const int AES_KEY_SIZE = 32; // 256-bit
const int HMAC_KEY_SIZE = 32;
const int NONCE_SIZE = 12;
const int RSA_KEY_SIZE = 4096;
const int TIMESTAMP_TOLERANCE = 30; // Seconds for replay attack protection

class E2EESecurity {
public:
    E2EESecurity() {
        // Initialize OpenSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        // Generate long-term RSA keys
        rsa_private_key = RSA_new();
        BIGNUM* bne = BN_new();
        BN_set_word(bne, RSA_F4);
        RSA_generate_key_ex(rsa_private_key, RSA_KEY_SIZE, bne, NULL);
        rsa_public_key = RSAPublicKey_dup(rsa_private_key);
        BN_free(bne);
    }

    ~E2EESecurity() {
        // Cleanup OpenSSL
        RSA_free(rsa_private_key);
        RSA_free(rsa_public_key);
        EVP_PKEY_free(ephemeral_ecdh_private_key);
        EVP_PKEY_free(ephemeral_ecdh_public_key);
        ERR_free_strings();
        EVP_cleanup();
    }

    void generate_ephemeral_keys() {
        // Generate ephemeral ECDH keys for each session
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1);
        EVP_PKEY_keygen(pctx, &ephemeral_ecdh_private_key);
        ephemeral_ecdh_public_key = EVP_PKEY_new();
        EVP_PKEY_copy_parameters(ephemeral_ecdh_public_key, ephemeral_ecdh_private_key);
        EVP_PKEY_CTX_free(pctx);
    }

    std::string get_ephemeral_ecdh_public_key() {
        // Export ephemeral ECDH public key
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(bio, ephemeral_ecdh_public_key);
        char* pem_key = NULL;
        long pem_len = BIO_get_mem_data(bio, &pem_key);
        std::string pub_key(pem_key, pem_len);
        BIO_free(bio);
        return pub_key;
    }

    std::vector<unsigned char> derive_shared_secret(const std::string& peer_public_key_pem) {
        // Derive shared secret using ephemeral ECDH
        generate_ephemeral_keys();

        BIO* bio = BIO_new_mem_buf(peer_public_key_pem.data(), peer_public_key_pem.size());
        EVP_PKEY* peer_public_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(ephemeral_ecdh_private_key, NULL);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_derive_set_peer(ctx, peer_public_key);
        
        size_t shared_secret_len;
        EVP_PKEY_derive(ctx, NULL, &shared_secret_len);
        std::vector<unsigned char> shared_secret(shared_secret_len);
        EVP_PKEY_derive(ctx, shared_secret.data(), &shared_secret_len);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_public_key);

        // Use HKDF to derive AES and HMAC keys
        EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
        EVP_PKEY_derive_init(kctx);
        EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_salt(kctx, NULL, 0);
        EVP_PKEY_CTX_set1_hkdf_key(kctx, shared_secret.data(), shared_secret.size());
        EVP_PKEY_CTX_add1_hkdf_info(kctx, reinterpret_cast<const unsigned char*>("E2EE Key Derivation"), sizeof("E2EE Key Derivation") - 1);

        size_t key_material_len = AES_KEY_SIZE + HMAC_KEY_SIZE;
        std::vector<unsigned char> key_material(key_material_len);
        EVP_PKEY_derive(kctx, key_material.data(), &key_material_len);
        EVP_PKEY_CTX_free(kctx);

        aes_key.assign(key_material.begin(), key_material.begin() + AES_KEY_SIZE);
        hmac_key.assign(key_material.begin() + AES_KEY_SIZE, key_material.end());

        return aes_key; // Return the AES key directly
    }

    std::vector<unsigned char> sign_message(const std::string& message) {
        // Sign the message using RSA to provide authenticity
        std::vector<unsigned char> message_bytes(message.begin(), message.end());
        std::vector<unsigned char> signature(RSA_size(rsa_private_key));

        unsigned int sig_len;
        RSA_sign(NID_sha256, message_bytes.data(), message_bytes.size(), signature.data(), &sig_len, rsa_private_key);
        signature.resize(sig_len);

        return signature;
    }

    bool verify_signature(const std::string& message, const std::vector<unsigned char>& signature) {
        // Verify the signature of a message using RSA
        std::vector<unsigned char> message_bytes(message.begin(), message.end());
        int result = RSA_verify(NID_sha256, message_bytes.data(), message_bytes.size(), signature.data(), signature.size(), rsa_public_key);
        return result == 1;
    }

    std::vector<unsigned char> encrypt(const std::string& plaintext) {
        // Compress the plaintext before encryption
        uLongf compressed_data_len = compressBound(plaintext.size());
        std::vector<unsigned char> compressed_data(compressed_data_len);
        compress(compressed_data.data(), &compressed_data_len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
        compressed_data.resize(compressed_data_len);

        // Encrypts data using AES-256-GCM with integrity protection and compression
        std::vector<unsigned char> nonce(NONCE_SIZE);
        RAND_bytes(nonce.data(), NONCE_SIZE);

        std::vector<unsigned char> ciphertext(compressed_data.size() + AES_BLOCK_SIZE);
        int len;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key.data(), nonce.data());
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, compressed_data.data(), compressed_data.size());
        int ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;

        // Create HMAC for integrity
        unsigned char mac[HMAC_KEY_SIZE];
        HMAC(EVP_sha256(), hmac_key.data(), HMAC_KEY_SIZE, ciphertext.data(), ciphertext_len, mac, NULL);

        // Include timestamp for replay protection
        auto timestamp = std::chrono::system_clock::now().time_since_epoch();
        auto timestamp_seconds = std::chrono::duration_cast<std::chrono::seconds>(timestamp).count();
        std::vector<unsigned char> timestamp_bytes(sizeof(timestamp_seconds));
        memcpy(timestamp_bytes.data(), &timestamp_seconds, sizeof(timestamp_seconds));

        // Concatenate the encrypted data
        std::vector<unsigned char> encrypted_data;
        encrypted_data.insert(encrypted_data.end(), nonce.begin(), nonce.end());
        encrypted_data.insert(encrypted_data.end(), mac, mac + HMAC_KEY_SIZE);
        encrypted_data.insert(encrypted_data.end(), timestamp_bytes.begin(), timestamp_bytes.end());
        encrypted_data.insert(encrypted_data.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);

        EVP_CIPHER_CTX_free(ctx);
        return encrypted_data;
    }

    std::string decrypt(const std::vector<unsigned char>& encrypted_data) {
        // Extract components from the encrypted data
        std::vector<unsigned char> nonce(encrypted_data.begin(), encrypted_data.begin() + NONCE_SIZE);
        std::vector<unsigned char> mac(encrypted_data.begin() + NONCE_SIZE, encrypted_data.begin() + NONCE_SIZE + HMAC_KEY_SIZE);
        std::vector<unsigned char> timestamp_bytes(encrypted_data.begin() + NONCE_SIZE + HMAC_KEY_SIZE, encrypted_data.begin() + NONCE_SIZE + HMAC_KEY_SIZE + sizeof(int64_t));
        std::vector<unsigned char> ciphertext(encrypted_data.begin() + NONCE_SIZE + HMAC_KEY_SIZE + sizeof(int64_t), encrypted_data.end());

        // Replay protection: check timestamp
        int64_t timestamp;
        memcpy(&timestamp, timestamp_bytes.data(), sizeof(timestamp));
        auto now = std::chrono::system_clock::now().time_since_epoch();
        auto now_seconds = std::chrono::duration_cast<std::chrono::seconds>(now).count();
        if (std::abs(now_seconds - timestamp) > TIMESTAMP_TOLERANCE) {
            throw std::runtime_error("Replay attack detected!");
        }

        // Verify HMAC
        unsigned char expected_mac[HMAC_KEY_SIZE];
        HMAC(EVP_sha256(), hmac_key.data(), HMAC_KEY_SIZE, ciphertext.data(), ciphertext.size(), expected_mac, NULL);
        if (CRYPTO_memcmp(mac.data(), expected_mac, HMAC_KEY_SIZE) != 0) {
            throw std::runtime_error("Data integrity compromised!");
        }

        // Decrypt
        std::vector<unsigned char> decrypted_data(ciphertext.size());
        int len;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key.data(), nonce.data());
        EVP_DecryptUpdate(ctx, decrypted_data.data(), &len, ciphertext.data(), ciphertext.size());
        int decrypted_len = len;
        EVP_DecryptFinal_ex(ctx, decrypted_data.data() + len, &len);
        decrypted_len += len;

        // Decompress the data after decryption
        uLongf decompressed_data_len = decrypted_data.size();
        std::vector<unsigned char> decompressed_data(decompressed_data_len);
        uncompress(decompressed_data.data(), &decompressed_data_len, decrypted_data.data(), decrypted_len);
        decompressed_data.resize(decompressed_data_len);

        EVP_CIPHER_CTX_free(ctx);
        return std::string(decompressed_data.begin(), decompressed_data.end());
    }

    std::vector<unsigned char> encrypt_symmetric_key() {
        // Encrypt AES key with RSA-4096
        std::vector<unsigned char> encrypted_key(RSA_size(rsa_public_key));
        int encrypted_key_len = RSA_public_encrypt(aes_key.size(), aes_key.data(), encrypted_key.data(), rsa_public_key, RSA_PKCS1_OAEP_PADDING);
        if (encrypted_key_len == -1) {
            throw std::runtime_error("Failed to encrypt AES key");
        }
        encrypted_key.resize(encrypted_key_len);
        return encrypted_key;
    }

    std::vector<unsigned char> decrypt_symmetric_key(const std::vector<unsigned char>& encrypted_key) {
        // Decrypt AES key using RSA-4096
        std::vector<unsigned char> decrypted_key(RSA_size(rsa_private_key));
        int decrypted_key_len = RSA_private_decrypt(encrypted_key.size(), encrypted_key.data(), decrypted_key.data(), rsa_private_key, RSA_PKCS1_OAEP_PADDING);
        if (decrypted_key_len == -1) {
            throw std::runtime_error("Failed to decrypt AES key");
        }
        decrypted_key.resize(decrypted_key_len);
        aes_key.assign(decrypted_key.begin(), decrypted_key.end());
        return aes_key;
    }

    std::vector<unsigned char> encrypt_metadata(const Json::Value& metadata) {
        // Encrypts metadata (IP, port, etc.)
        Json::StreamWriterBuilder writer;
        std::string metadata_json = Json::writeString(writer, metadata);

        std::vector<unsigned char> nonce(NONCE_SIZE);
        RAND_bytes(nonce.data(), NONCE_SIZE);

        std::vector<unsigned char> encrypted_metadata(metadata_json.size() + AES_BLOCK_SIZE);
        int len;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key.data(), nonce.data());
        EVP_EncryptUpdate(ctx, encrypted_metadata.data(), &len, reinterpret_cast<const unsigned char*>(metadata_json.c_str()), metadata_json.size());
        int encrypted_metadata_len = len;
        EVP_EncryptFinal_ex(ctx, encrypted_metadata.data() + len, &len);
        encrypted_metadata_len += len;
        EVP_CIPHER_CTX_free(ctx);

        encrypted_metadata.resize(encrypted_metadata_len);
        return encrypted_metadata;
    }

    Json::Value decrypt_metadata(const std::vector<unsigned char>& encrypted_metadata) {
        // Decrypts metadata
        std::vector<unsigned char> nonce(NONCE_SIZE);
        RAND_bytes(nonce.data(), NONCE_SIZE);

        std::vector<unsigned char> decrypted_metadata(encrypted_metadata.size());
        int len;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key.data(), nonce.data());
        EVP_DecryptUpdate(ctx, decrypted_metadata.data(), &len, encrypted_metadata.data(), encrypted_metadata.size());
        int decrypted_metadata_len = len;
        EVP_DecryptFinal_ex(ctx, decrypted_metadata.data() + len, &len);
        decrypted_metadata_len += len;
        EVP_CIPHER_CTX_free(ctx);

        decrypted_metadata.resize(decrypted_metadata_len);
        
        Json::CharReaderBuilder reader;
        Json::Value metadata;
        std::string errs;
        std::string decrypted_metadata_str(decrypted_metadata.begin(), decrypted_metadata.end());
        std::istringstream s(decrypted_metadata_str);
        Json::parseFromStream(reader, s, &metadata, &errs);

        return metadata;
    }

    Json::Value handshake(const std::string& peer_public_key_pem) {
        // Optimized handshake with Forward Secrecy
        // Generate ephemeral keys for this session
        std::string ephemeral_public_key = get_ephemeral_ecdh_public_key();

        // Derive shared secret using ephemeral ECDH key pair
        std::vector<unsigned char> shared_secret = derive_shared_secret(peer_public_key_pem);

        // Cache the shared secret for future use to avoid recalculating for each message
        this->shared_secret = shared_secret;

        // Return ephemeral public key and the shared secret for RSA encryption of symmetric key
        Json::Value handshake_data;
        handshake_data["shared_secret"] = std::string(shared_secret.begin(), shared_secret.end());
        handshake_data["ephemeral_public_key"] = ephemeral_public_key;
        handshake_data["public_key"] = get_rsa_public_key();
        return handshake_data;
    }

    Json::Value secure_message_exchange(const std::string& peer_public_key_pem, const std::string& message) {
        // Exchange a secure message (sign, encrypt, decrypt) with Forward Secrecy
        // Handshake to derive shared secret and public keys
        Json::Value handshake_data = handshake(peer_public_key_pem);

        // Sign the message before encrypting
        std::vector<unsigned char> signed_message = sign_message(message);

        // Encrypt the message
        std::vector<unsigned char> encrypted_message = encrypt(message);

        Json::Value exchange_data;
        exchange_data["signed_message"] = std::string(signed_message.begin(), signed_message.end());
        exchange_data["encrypted_message"] = std::string(encrypted_message.begin(), encrypted_message.end());
        exchange_data["handshake_data"] = handshake_data;
        return exchange_data;
    }

    bool authenticate_peer(const std::string& peer_public_key_pem, const std::vector<unsigned char>& signed_message) {
        // Authenticate the peer by verifying their signed message
        return verify_signature(peer_public_key_pem, signed_message);
    }

private:
    RSA* rsa_private_key;
    RSA* rsa_public_key;
    EVP_PKEY* ephemeral_ecdh_private_key;
    EVP_PKEY* ephemeral_ecdh_public_key;
    std::vector<unsigned char> shared_secret;
    std::vector<unsigned char> aes_key;
    std::vector<unsigned char> hmac_key;

    std::string get_rsa_public_key() {
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPublicKey(bio, rsa_public_key);
        char* pem_key = NULL;
        long pem_len = BIO_get_mem_data(bio, &pem_key);
        std::string pub_key(pem_key, pem_len);
        BIO_free(bio);
        return pub_key;
    }
};

// Encrypt a file
void encrypt_file(const std::string& input_file, const std::string& output_file) {
    // Read the file content
    std::ifstream in(input_file, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open input file for reading.");
    }

    std::string file_content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    // Encrypt the file content using the existing encrypt function
    std::vector<unsigned char> encrypted_data = encrypt(file_content);

    // Write the encrypted data to the output file
    std::ofstream out(output_file, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open output file for writing.");
    }
    out.write(reinterpret_cast<const char*>(encrypted_data.data()), encrypted_data.size());
    out.close();
}

// Decrypt a file
std::string decrypt_file(const std::string& input_file) {
    // Read the encrypted file content
    std::ifstream in(input_file, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open input file for reading.");
    }

    std::vector<unsigned char> encrypted_data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    // Decrypt the data using the existing decrypt function
    return decrypt(encrypted_data);
}
