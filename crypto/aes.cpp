#include <openssl/aes.h>
#include <cstring>
#include <iostream>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void encrypt_decrypt_example(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext, unsigned char *ciphertext, unsigned char *decryptedtext) {
    AES_KEY encryptKey, decryptKey;

    // Set encryption key
    if (AES_set_encrypt_key(key, 256, &encryptKey) < 0) {
        handleErrors();
    }

    // Set decryption key
    if (AES_set_decrypt_key(key, 256, &decryptKey) < 0) {
        handleErrors();
    }

    // Encrypt
    AES_ige_encrypt(plaintext, ciphertext, strlen((const char *)plaintext), &encryptKey, (unsigned char *)iv, AES_ENCRYPT);
    
    // Decrypt
    AES_ige_encrypt(ciphertext, decryptedtext, strlen((const char *)plaintext), &decryptKey, (unsigned char *)iv, AES_DECRYPT);
}

int main() {
    // 256-bit key (32 bytes)
    const unsigned char key[32] = "01234567890123456789012345678901";

    // Initialization vector (IV) for AES-IGE mode (32 bytes)
    unsigned char iv[32] = "01234567890123456789012345678901";

    // Plaintext to encrypt
    const unsigned char plaintext[] = "This is a test text for AES-IGE.";

    // Buffers for ciphertext and decrypted text
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    // Encrypt and decrypt
    encrypt_decrypt_example(key, iv, plaintext, ciphertext, decryptedtext);

    // Null-terminate the decrypted text
    decryptedtext[strlen((const char *)plaintext)] = '\0';

    // Display results
    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Ciphertext: ";
    for (int i = 0; i < strlen((const char *)plaintext); i++) {
        printf("%02x", ciphertext[i]);
    }
    std::cout << std::endl;
    std::cout << "Decrypted text: " << decryptedtext << std::endl;

    return 0;
}
