// Script TLS paramétrable non-interactif
//
// Build :
//    g++ -std=c++17 custom_client.cpp -o custom_client -lssl -lcrypto
//
// Run :
//    ./custom_client <addr_ip> <port> <protocol> <ciphersuite> <certificate_verification>
//
// Exemple :
//    ./custom_client 127.0.0.1 443 tls12 "ECDHE-RSA-AES128-GCM-SHA256" 1

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

using namespace std;

static void init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

int tcp_connect(const string &host, const string &port) {
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    if (ret != 0) {
        cerr << "getaddrinfo: " << gai_strerror(ret) << "\n";
        return -1;
    }

    int sock = -1;
    for (auto rp = res; rp != nullptr; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) continue;

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;

        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);
    return sock;
}

void print_cert_info(SSL *ssl) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        cout << "[!] No certificate presented by server.\n";
        return;
    }

    cout << "\n=== Server Certificate Info ===\n";

    char subject[256];
    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
    cout << "Subject: " << subject << "\n";

    char issuer[256];
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
    cout << "Issuer : " << issuer << "\n";

    ASN1_TIME *nb = X509_get_notBefore(cert);
    ASN1_TIME *na = X509_get_notAfter(cert);

    BIO *bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, nb);
    char *data;
    long len = BIO_get_mem_data(bio, &data);
    cout << "Not Before: " << string(data, len) << "\n";
    BIO_free(bio);

    bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, na);
    len = BIO_get_mem_data(bio, &data);
    cout << "Not After : " << string(data, len) << "\n";
    BIO_free(bio);

    long verify_res = SSL_get_verify_result(ssl);
    cout << "Verification: ";
    if (verify_res == X509_V_OK)
        cout << "OK\n";
    else
        cout << "FAILED (" << X509_verify_cert_error_string(verify_res) << ")\n";

    X509_free(cert);
    cout << "-------------------------------\n";
}

int main(int argc, char** argv) {

    if (argc != 6) {
        cerr << "Usage: " << argv[0]
             << " <host> <port> <protocol> <ciphersuite> <cert_verify>\n";
        cerr << "protocol: tls12 | tls13\n";
        cerr << "cert_verify: 0 or 1\n";
        return 1;
    }

    string host       = argv[1];
    string port       = argv[2];
    string protocol   = argv[3];
    string cipher     = argv[4];
    int verify        = stoi(argv[5]);

    int min_ver = 0, max_ver = 0;

    if (protocol == "tls12") {
        min_ver = max_ver = TLS1_2_VERSION;
    } else if (protocol == "tls13") {
        min_ver = max_ver = TLS1_3_VERSION;
    } else {
        cerr << "Invalid protocol: use tls12 or tls13.\n";
        return 1;
    }

    init_openssl();

    cout << "Connecting to " << host << ":" << port << "\n";
    cout << "Protocol: " << protocol << "\n";
    cout << "Cipher  : " << cipher << "\n";
    cout << "Verify  : " << verify << "\n";

    int sock = tcp_connect(host, port);
    if (sock < 0) {
        cerr << "TCP connection failed.\n";
        return 1;
    }

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    SSL_CTX_set_min_proto_version(ctx, min_ver);
    SSL_CTX_set_max_proto_version(ctx, max_ver);

    if (protocol == "tls12")
        SSL_CTX_set_cipher_list(ctx, cipher.c_str());
    else
        SSL_CTX_set_ciphersuites(ctx, cipher.c_str());

    if (verify) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_default_verify_paths(ctx);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, host.c_str());

    cout << "\nPerforming TLS handshake...\n";

    int ret = SSL_connect(ssl);
    if (ret != 1) {
        int err = SSL_get_error(ssl, ret);
        cerr << "SSL_connect failed: " << err << "\n";
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    cout << "Connected using " << SSL_get_version(ssl)
         << " / " << SSL_get_cipher(ssl) << "\n";

    print_cert_info(ssl);

    string req = "GET / HTTP/1.1\r\nHost: " + host +
                 "\r\nConnection: close\r\n\r\n";

    SSL_write(ssl, req.c_str(), req.size());

    cout << "\n--- Server Response ---\n";
    char buf[4096];
    while (true) {
        int r = SSL_read(ssl, buf, sizeof(buf));
        if (r > 0) {
            cout.write(buf, r);
            continue;
        }

        int e = SSL_get_error(ssl, r);
        if (e == SSL_ERROR_ZERO_RETURN) {
            cout << "\n[Server] Closed TLS cleanly.\n";
            break;
        }
        if (e == SSL_ERROR_SYSCALL) {
            cout << "\n[Server] Closed TCP unexpectedly.\n";
            break;
        }
        cout << "\nSSL_read error: " << e << "\n";
        break;
    }

    cout << "\nClosing connection\n";

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return 0;
}