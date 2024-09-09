#include "DTLSClient.hpp"

OpenSSLWrapper::DTLSClient::DTLSClient(std::string& ca)
    : DTLSConnection(ca) {
    // 初始化 SSL
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    // 初始化 DTLS 连接所需的 SSL_CTX
    ctxInit();
}
