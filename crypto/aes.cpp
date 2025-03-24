#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <filesystem>
#include <windows.h>
#include <cmath>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/ecdh.h>
#include <pcap.h>
#include <winsock2.h>

// HydraX namespace for handling various commands and operations
namespace HydraX {
    // Echo function to print text
    void echo(const std::string &text) {
        std::cout << text << std::endl;
    }

    // Write function to print text without newline
    void write(const std::string &text) {
        std::cout << text;
    }

    // Log function to record logs
    void log(const std::string &text) {
        std::ofstream log_file("hydrax.log", std::ios_base::app);
        log_file << text << std::endl;
    }

    // File system operations
    std::string read_file(const std::string &file_path) {
        std::ifstream file(file_path);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open file: " + file_path);
        }
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }

    void write_file(const std::string &file_path, const std::string &content) {
        std::ofstream file(file_path);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open file: " + file_path);
        }
        file << content;
    }

    std::vector<std::string> list_directory_files(const std::string &path) {
        std::vector<std::string> file_list;
        for (const auto &entry : std::filesystem::directory_iterator(path)) {
            file_list.push_back(entry.path().string());
        }
        return file_list;
    }

    std::string get_current_directory() {
        return std::filesystem::current_path().string();
    }

    void execute_shell_command(const std::string &command) {
        system(command.c_str());
    }

    void delete_file(const std::string &file_path) {
        std::filesystem::remove(file_path);
    }

    // System monitoring functions
    MEMORYSTATUSEX get_memory_info() {
        MEMORYSTATUSEX statex;
        statex.dwLength = sizeof(statex);
        GlobalMemoryStatusEx(&statex);
        return statex;
    }

    double get_cpu_usage() {
        FILETIME idleTime, kernelTime, userTime;
        GetSystemTimes(&idleTime, &kernelTime, &userTime);
        return (double)(userTime.dwLowDateTime + userTime.dwHighDateTime);
    }

    ULARGE_INTEGER get_disk_usage(const std::string &path) {
        ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
        GetDiskFreeSpaceExA(path.c_str(), &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes);
        return totalNumberOfBytes;
    }

    // TLS functions
    void tls_generate_certificate(const std::string &cert_params) {
        EVP_PKEY *pkey = EVP_PKEY_new();
        X509 *x509 = X509_new();

        // Generate key
        RSA *rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        EVP_PKEY_assign_RSA(pkey, rsa);

        // Set certificate details
        X509_set_version(x509, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 0);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
        X509_set_pubkey(x509, pkey);

        // Sign the certificate
        X509_sign(x509, pkey, EVP_sha256());

        // Write to file
        FILE *pkey_file = fopen("private.key", "wb");
        PEM_write_PrivateKey(pkey_file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(pkey_file);

        FILE *x509_file = fopen("certificate.crt", "wb");
        PEM_write_X509(x509_file, x509);
        fclose(x509_file);

        EVP_PKEY_free(pkey);
        X509_free(x509);
    }

    void tls_connect(const std::string &host, int port, const std::string &cert_file) {
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        SSL *ssl;
        int server;

        server = socket(AF_INET, SOCK_STREAM, 0);

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

        connect(server, (struct sockaddr*)&addr, sizeof(addr));

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, server);

        SSL_CTX_load_verify_locations(ctx, cert_file.c_str(), nullptr);

        SSL_connect(ssl);
    }

    void tls_handshake(int socket) {
        SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, socket);
        SSL_accept(ssl);
    }

    void tls_encrypt_data(const std::string &session_key, const std::string &data) {
        unsigned char outbuf[1024];
        int outlen, tmplen;
        EVP_CIPHER_CTX *ctx;

        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char *)session_key.c_str(), (unsigned char *)"0123456789012345");

        EVP_EncryptUpdate(ctx, outbuf, &outlen, (unsigned char *)data.c_str(), data.length());
        EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen);

        EVP_CIPHER_CTX_free(ctx);
    }

    void tls_decrypt_data(const std::string &session_key, const std::string &encrypted_data) {
        unsigned char outbuf[1024];
        int outlen, tmplen;
        EVP_CIPHER_CTX *ctx;

        ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char *)session_key.c_str(), (unsigned char *)"0123456789012345");

        EVP_DecryptUpdate(ctx, outbuf, &outlen, (unsigned char *)encrypted_data.c_str(), encrypted_data.length());
        EVP_DecryptFinal_ex(ctx, outbuf + outlen, &tmplen);

        EVP_CIPHER_CTX_free(ctx);
    }

    void tls_verify_certificate(const std::string &cert_file, const std::string &ca_file) {
        FILE *fp = fopen(cert_file.c_str(), "r");
        X509 *cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
        fclose(fp);

        fp = fopen(ca_file.c_str(), "r");
        X509 *ca_cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
        fclose(fp);

        X509_STORE *store = X509_STORE_new();
        X509_STORE_add_cert(store, ca_cert);

        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(ctx, store, cert, nullptr);
        X509_STORE_CTX_verify(ctx);

        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        X509_free(cert);
        X509_free(ca_cert);
    }

    // Sniffer functions
    void save_capture_to_file(pcap_t *capture, const std::string &file_path) {
        pcap_dumper_t *dumper = pcap_dump_open(capture, file_path.c_str());
        if (!dumper) {
            throw std::runtime_error("Failed to open dump file: " + file_path);
        }
        pcap_loop(capture, 0, pcap_dump, reinterpret_cast<u_char *>(dumper));
        pcap_dump_close(dumper);
    }

    std::string get_packet_protocol(const struct pcap_pkthdr *packet) {
        // Example implementation to return protocol as string
        return "TCP";
    }

    void extract_tcp_payload(const struct pcap_pkthdr *packet) {
        // Example implementation to extract TCP payload
    }

    void extract_udp_payload(const struct pcap_pkthdr *packet) {
        // Example implementation to extract UDP payload
    }

    void extract_icmp_payload(const struct pcap_pkthdr *packet) {
        // Example implementation to extract ICMP payload
    }

    void print_packet_details(const struct pcap_pkthdr *packet) {
        // Example implementation to print packet details
    }

    void filter_packets(pcap_t *capture, const std::string &filter_expression) {
        struct bpf_program fp;
        if (pcap_compile(capture, &fp, filter_expression.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            throw std::runtime_error("Failed to compile filter: " + filter_expression);
        }
        if (pcap_setfilter(capture, &fp) == -1) {
            throw std::runtime_error("Failed to set filter: " + filter_expression);
        }
    }

    void start_live_capture(const std::string &interface) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            throw std::runtime_error("Failed to open device: " + interface);
        }
        pcap_loop(handle, 0, [](u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
            // Example implementation to handle captured packets
        }, nullptr);
        pcap_close(handle);
    }

    void open_capture_file(const std::string &file_path) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_offline(file_path.c_str(), errbuf);
        if (handle == nullptr) {
            throw std::runtime_error("Failed to open file: " + file_path);
        }
        pcap_loop(handle, 0, [](u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
            // Example implementation to handle packets from file
        }, nullptr);
        pcap_close(handle);
    }

    // Socket functions
    void socket_create() {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            throw std::runtime_error("Failed to create socket");
        }
    }

    void socket_connect(SOCKET &sock, const std::string &address, int port) {
        sockaddr_in clientService;
        clientService.sin_family = AF_INET;
        clientService.sin_addr.s_addr = inet_addr(address.c_str());
        clientService.sin_port = htons(port);

        if (connect(sock, (SOCKADDR *)&clientService, sizeof(clientService)) == SOCKET_ERROR) {
            throw std::runtime_error("Failed to connect to server");
        }
    }

    void socket_bind(SOCKET &sock, int port) {
        sockaddr_in service;
        service.sin_family = AF_INET;
        service.sin_addr.s_addr = INADDR_ANY;
        service.sin_port = htons(port);

        if (bind(sock, (SOCKADDR *)&service, sizeof(service)) == SOCKET_ERROR) {
            throw std::runtime_error("Failed to bind socket");
        }
    }

    void socket_listen(SOCKET &sock) {
        if (listen(sock, SOMAXCONN) == SOCKET_ERROR) {
            throw std::runtime_error("Failed to listen on socket");
        }
    }

    void socket_accept(SOCKET &sock) {
        SOCKET acceptSocket = accept(sock, nullptr, nullptr);
        if (acceptSocket == INVALID_SOCKET) {
            throw std::runtime_error("Failed to accept connection");
        }
    }

    void socket_send(SOCKET &sock, const std::string &data) {
        send(sock, data.c_str(), data.length(), 0);
    }

    void socket_receive(SOCKET &sock) {
        char recvbuf[512];
        int recvbuflen = 512;
        recv(sock, recvbuf, recvbuflen, 0);
    }

    void socket_close(SOCKET &sock) {
        closesocket(sock);
        WSACleanup();
    }

    void socket_settimeout(SOCKET &sock, int timeout) {
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    }

    // Tech9 functions (hashing and encryption)
    std::string hash_string_md5(const std::string &input) {
        unsigned char hash[MD5_DIGEST_LENGTH];
        MD5((unsigned char *)input.c_str(), input.length(), hash);
        std::stringstream ss;
        for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
            ss << std::hex << (int)hash[i];
        }
        return ss.str();
    }

    std::string hash_string_sha1(const std::string &input) {
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1((unsigned char *)input.c_str(), input.length(), hash);
        std::stringstream ss;
        for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
            ss << std::hex << (int)hash[i];
        }
        return ss.str();
    }

    std::string hash_string_sha256(const std::string &input) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char *)input.c_str(), input.length(), hash);
        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            ss << std::hex << (int)hash[i];
        }
        return ss.str();
    }

    std::string hash_string_sha512(const std::string &input) {
        unsigned char hash[SHA512_DIGEST_LENGTH];
        SHA512((unsigned char *)input.c_str(), input.length(), hash);
        std::stringstream ss;
        for (int i = 0; i < SHA512_DIGEST_LENGTH; ++i) {
            ss << std::hex << (int)hash[i];
        }
        return ss.str();
    }

    std::string hash_string_sha3(const std::string &input) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA3_256((unsigned char *)input.c_str(), input.length(), hash);
        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            ss << std::hex << (int)hash[i];
        }
        return ss.str();
    }

    void generate_keypair_rsa() {
        RSA *rsa = RSA_new();
        BIGNUM *bn = BN_new();
        BN_set_word(bn, RSA_F4);
        RSA_generate_key_ex(rsa, 2048, bn, nullptr);

        BIO *pri = BIO_new_file("rsa_private.pem", "w");
        PEM_write_bio_RSAPrivateKey(pri, rsa, nullptr, nullptr, 0, nullptr, nullptr);
        BIO_free_all(pri);

        BIO *pub = BIO_new_file("rsa_public.pem", "w");
        PEM_write_bio_RSAPublicKey(pub, rsa);
        BIO_free_all(pub);

        RSA_free(rsa);
        BN_free(bn);
    }

    void generate_keypair_aes() {
        unsigned char key[32];
        RAND_bytes(key, 32);

        FILE *key_file = fopen("aes_key.bin", "wb");
        fwrite(key, 1, 32, key_file);
        fclose(key_file);
    }

    void encrypt_rsa(const std::string &public_key, const std::string &data) {
        BIO *pub = BIO_new_mem_buf(public_key.c_str(), -1);
        RSA *rsa = PEM_read_bio_RSAPublicKey(pub, nullptr, nullptr, nullptr);

        std::vector<unsigned char> encrypted(RSA_size(rsa));
        int len = RSA_public_encrypt(data.length(), (unsigned char *)data.c_str(), encrypted.data(), rsa, RSA_PKCS1_OAEP_PADDING);

        std::ofstream outfile("encrypted_rsa.bin", std::ios::binary);
        outfile.write((char *)encrypted.data(), len);
        outfile.close();

        RSA_free(rsa);
        BIO_free_all(pub);
    }

    void encrypt_aes(const std::string &key, const std::string &data) {
        unsigned char outbuf[1024];
        int outlen, tmplen;
        EVP_CIPHER_CTX *ctx;

        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char *)key.c_str(), (unsigned char *)"0123456789012345");

        EVP_EncryptUpdate(ctx, outbuf, &outlen, (unsigned char *)data.c_str(), data.length());
        EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen);

        std::ofstream outfile("encrypted_aes.bin", std::ios::binary);
        outfile.write((char *)outbuf, outlen + tmplen);
        outfile.close();

        EVP_CIPHER_CTX_free(ctx);
    }

    void verify_signature(const std::string &public_key, const std::string &message, const std::string &signature) {
        BIO *pub = BIO_new_mem_buf(public_key.c_str(), -1);
        RSA *rsa = PEM_read_bio_RSAPublicKey(pub, nullptr, nullptr, nullptr);

        if (RSA_verify(NID_sha256, (unsigned char *)message.c_str(), message.length(), (unsigned char *)signature.c_str(), signature.length(), rsa) == 1) {
            std::cout << "Signature verified" << std::endl;
        } else {
            std::cout << "Signature verification failed" << std::endl;
        }

        RSA_free(rsa);
        BIO_free_all(pub);
    }

    void sign(const std::string &private_key, const std::string &data) {
        BIO *pri = BIO_new_mem_buf(private_key.c_str(), -1);
        RSA *rsa = PEM_read_bio_RSAPrivateKey(pri, nullptr, nullptr, nullptr);

        std::vector<unsigned char> signature(RSA_size(rsa));
        unsigned int sig_len;
        RSA_sign(NID_sha256, (unsigned char *)data.c_str(), data.length(), signature.data(), &sig_len, rsa);

        std::ofstream outfile("signature.bin", std::ios::binary);
        outfile.write((char *)signature.data(), sig_len);
        outfile.close();

        RSA_free(rsa);
        BIO_free_all(pri);
    }

        void compute_shared_secret_dh(const std::string &private_key, const std::string &peer_public_key) {
        BIO *pri = BIO_new_mem_buf(private_key.c_str(), -1);
        DH *dh = PEM_read_bio_DHparams(pri, nullptr, nullptr, nullptr);
        BIO_free_all(pri);

        BIO *pub = BIO_new_mem_buf(peer_public_key.c_str(), -1);
        DH *peer_dh = PEM_read_bio_DHparams(pub, nullptr, nullptr, nullptr);
        BIO_free_all(pub);

        unsigned char *secret = (unsigned char *)OPENSSL_malloc(DH_size(dh));
        int secret_size = DH_compute_key(secret, peer_dh->pub_key, dh);

        std::ofstream outfile("shared_secret.bin", std::ios::binary);
        outfile.write((char *)secret, secret_size);
        outfile.close();

        OPENSSL_free(secret);
        DH_free(dh);
        DH_free(peer_dh);
    }

    void compute_shared_secret_ecdh(const std::string &private_key, const std::string &peer_public_key) {
        BIO *pri = BIO_new_mem_buf(private_key.c_str(), -1);
        EC_KEY *ec_key = PEM_read_bio_ECPrivateKey(pri, nullptr, nullptr, nullptr);
        BIO_free_all(pri);

        BIO *pub = BIO_new_mem_buf(peer_public_key.c_str(), -1);
        EC_KEY *peer_ec_key = PEM_read_bio_EC_PUBKEY(pub, nullptr, nullptr, nullptr);
        BIO_free_all(pub);

        unsigned char *secret = (unsigned char *)OPENSSL_malloc(ECDH_size(ec_key));
        int secret_size = ECDH_compute_key(secret, ECDH_size(ec_key), EC_KEY_get0_public_key(peer_ec_key), ec_key, nullptr);

        std::ofstream outfile("ecdh_shared_secret.bin", std::ios::binary);
        outfile.write((char *)secret, secret_size);
        outfile.close();

        OPENSSL_free(secret);
        EC_KEY_free(ec_key);
        EC_KEY_free(peer_ec_key);
    }

    void generate_ecdh_shared_key(const std::string &peer_public_key) {
        EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        EC_KEY_generate_key(ec_key);

        BIO *pub = BIO_new_mem_buf(peer_public_key.c_str(), -1);
        EC_KEY *peer_ec_key = PEM_read_bio_EC_PUBKEY(pub, nullptr, nullptr, nullptr);
        BIO_free_all(pub);

        unsigned char *secret = (unsigned char *)OPENSSL_malloc(ECDH_size(ec_key));
        int secret_size = ECDH_compute_key(secret, ECDH_size(ec_key), EC_KEY_get0_public_key(peer_ec_key), ec_key, nullptr);

        std::ofstream outfile("ecdh_shared_key.bin", std::ios::binary);
        outfile.write((char *)secret, secret_size);
        outfile.close();

        OPENSSL_free(secret);
        EC_KEY_free(ec_key);
        EC_KEY_free(peer_ec_key);
    }

    void derive_key_from_secret(const std::string &secret, const std::string &salt, const std::string &info) {
        unsigned char derived_key[32];
        const EVP_MD *md = EVP_sha256();

        PKCS5_PBKDF2_HMAC(secret.c_str(), secret.length(), (unsigned char *)salt.c_str(), salt.length(), 10000, md, sizeof(derived_key), derived_key);

        std::ofstream outfile("derived_key.bin", std::ios::binary);
        outfile.write((char *)derived_key, sizeof(derived_key));
        outfile.close();
    }
}
