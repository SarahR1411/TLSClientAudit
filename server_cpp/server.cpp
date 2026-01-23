/*
Build :
   g++ -std=c++17 server.cpp -o tls_server -lssl -lcrypto

Run :
   ./tls_server
*/

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <vector>
#include <ctime>
#include <iomanip>

static void print_time() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_r(&t, &tm);
    std::cout << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
}

/*
    Callback ClientHello
 */
int client_hello_cb(SSL* ssl, int* al, void* arg) {
    (void)al;
    (void)arg;

    std::cout << "----- ClientHello reçu -----\n";
    std::cout << "Date        : ";
    print_time();
    std::cout << "\n";

    /* IP source / destination */
    int fd = SSL_get_fd(ssl);

    sockaddr_in src{}, dst{};
    socklen_t len = sizeof(sockaddr_in);

    getpeername(fd, (sockaddr*)&src, &len);
    getsockname(fd, (sockaddr*)&dst, &len);

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &src.sin_addr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &dst.sin_addr, dst_ip, sizeof(dst_ip));

    std::cout << "IP source   : " << src_ip << "\n";
    std::cout << "IP dest     : " << dst_ip << "\n";

    /* SNI */
    const unsigned char* ext_data;
    size_t ext_len;

    if (SSL_client_hello_get0_ext(
            ssl,
            TLSEXT_TYPE_server_name,
            &ext_data,
            &ext_len)) {

        if (ext_len >= 5) {
            uint16_t sni_len = (ext_data[3] << 8) | ext_data[4];
            std::string sni(
                reinterpret_cast<const char*>(ext_data + 5),
                sni_len
            );
            std::cout << "SNI         : " << sni << "\n";
        } else {
            std::cout << "SNI         : invalide\n";
        }
    } else {
        std::cout << "SNI         : absent\n";
    }

    /* Cipher suites */
    const unsigned char* ciphers;
    size_t cipher_len;

    cipher_len = SSL_client_hello_get0_ciphers(ssl, &ciphers);

    std::cout << "CipherSuites:\n";
    for (size_t i = 0; i + 1 < cipher_len; i += 2) {
        uint16_t cs = (ciphers[i] << 8) | ciphers[i + 1];
        std::cout << "  - 0x"
                  << std::hex << std::setw(4) << std::setfill('0')
                  << cs << std::dec << "\n";
    }

    std::cout << "----------------------------\n\n";

    return SSL_CLIENT_HELLO_SUCCESS;
}

void info_cb(const SSL* ssl, int where, int ret) {
    if (where & SSL_CB_ALERT) {
        const char* dir = (where & SSL_CB_READ) ? "read" : "write";
        std::cerr << "[ALERT] (" << dir << ") "
                  << SSL_alert_type_string_long(ret) << " : "
                  << SSL_alert_desc_string_long(ret) << "\n";
    }
}

void print_connection_status(SSL* ssl) {
    std::cout << "=== Statut connexion ===\n";

    const char* version = SSL_get_version(ssl);
    std::cout << "TLS version : " << (version ? version : "N/A") << "\n";

    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        std::cout << "Cipher      : "
                  << SSL_CIPHER_get_name(cipher) << "\n";
    } else {
        std::cout << "Cipher      : non négocié\n";
    }

    if (SSL_is_init_finished(ssl)) {
        std::cout << "Handshake terminé, certificat accepté.\n";
    } else {
        std::cout << "Handshake interrompu, certificat peut-être rejeté.\n";
    }

    std::cout << "========================\n";
}

enum FaultMode {
    FAULT_NONE,
    FAULT_BAD_VERSION,
    FAULT_BAD_CIPHER,
    FAULT_BAD_CERT
};

int main() {
    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /* Certificat serveur */
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 || // Manquant : certificat valide permettant de faire les tests
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* Callback ClientHello */
    SSL_CTX_set_client_hello_cb(ctx, client_hello_cb, nullptr);


    SSL_CTX_set_info_callback(ctx, info_cb);


    FaultMode fault_mode = FAULT_BAD_CERT;


    if (fault_mode == FAULT_BAD_VERSION) {
        SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_VERSION); // TLS 1.0 forcé (ne marche pas pour l'instant, version de Openssl incompatible)
    }
    if (fault_mode == FAULT_BAD_CIPHER) {
        SSL_CTX_set_ciphersuites(ctx, ""); // Manque fonction pour extraire une ciphersuite vulnérable du ClientHello
    }

    if (fault_mode == FAULT_BAD_CERT) {
        SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM);
    }

    /* Socket TCP */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8080);

    bind(server_fd, (sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 10);

    std::cout << "Serveur TLS en écoute sur le port 8080\n";

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        int ret = SSL_accept(ssl);
        if (ret <= 0) {
            print_connection_status(ssl);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        print_connection_status(ssl);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}