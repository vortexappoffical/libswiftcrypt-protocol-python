#pragma once

#include <string>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <zlib.h>
#include <json/json.h>

class E2EESecurity {
public:
    E2EESecurity();
    ~E2EESecurity();

    void generate_ephemeral_keys();
    std::string get_ephemeral_ecdh_public_key();
    std::vector<unsigned char> derive_shared_secret(const std::string& peer_public_key_pem);
    std::vector<unsigned char> sign_message(const std::string& message);
    bool verify_signature(const std::string& message, const std::vector<unsigned char>& signature);
    std::vector<unsigned char> encrypt(const std::string& plaintext);
    std::string decrypt(const std::vector<unsigned char>& encrypted_data);
    std::vector<unsigned char> encrypt_symmetric_key();
    std::vector<unsigned char> decrypt_symmetric_key(const std::vector<unsigned char>& encrypted_key);
    std::vector<unsigned char> encrypt_metadata(const Json::Value& metadata);
    Json::Value decrypt_metadata(const std::vector<unsigned char>& encrypted_metadata);
    Json::Value handshake(const std::string& peer_public_key_pem);
    Json::Value secure_message_exchange(const std::string& peer_public_key_pem, const std::string& message);
    bool authenticate_peer(const std::string& peer_public_key_pem, const std::vector<unsigned char>& signed_message);

private:
    EVP_PKEY* rsa_private_key;
    EVP_PKEY* rsa_public_key;
    EVP_PKEY* ephemeral_ecdh_private_key;
    EVP_PKEY* ephemeral_ecdh_public_key;
    std::vector<unsigned char> shared_secret;
    std::vector<unsigned char> aes_key;
    std::vector<unsigned char> hmac_key;

    std::string get_rsa_public_key();
};

void encrypt_file(const std::string& input_file, const std::string& output_file);
std::string decrypt_file(const std::string& input_file);
