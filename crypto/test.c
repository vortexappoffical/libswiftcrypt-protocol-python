#include <openssl/opensslv.h>
#include <stdio.h>

int main() {
    printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    return 0;
}
