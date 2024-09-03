#include "DTLSConnection.hpp"
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
OpenSSLWrapper::DTLSConnection::DTLSConnection(SocketType type)
    : ctx_(nullptr), socket_fd_(-1), type_(type) {
    // 初始化 SSL
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    // 初始化 DTLS 连接所需的 SSL_CTX
    ctx_ = SSL_CTX_new(type == SocketType::Server ? DTLS_server_method() : DTLS_client_method());
    if (!ctx_) {
        std::cout << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
    }
}

OpenSSLWrapper::DTLSConnection::~DTLSConnection() {
    disconnect();
    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
    EVP_cleanup();
}
bool OpenSSLWrapper::DTLSConnection::setCA(const std::string& ca){
    if (!ctx_) {
        std::cout << "SSL_CTX is not initialized" << std::endl;
        return false;
    }
    // 如果需要双向认证
    if (!SSL_CTX_load_verify_locations(ctx_, ca.c_str(), nullptr)) {
        std::cout << "Error loading CA certificate.\n" << std::endl;
        return false;
    }
    return true;
}

bool OpenSSLWrapper::DTLSConnection::setCertificate(const std::string& certFile, const std::string& keyFile) {
    if (!ctx_) {
        std::cout << "SSL_CTX is not initialized" << std::endl;
        return false;
    }

    // 加载证书文件
    if (SSL_CTX_use_certificate_file(ctx_, certFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cout << "Failed to load certificate" << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    // 加载私钥文件
    if (SSL_CTX_use_PrivateKey_file(ctx_, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cout << "Failed to load private key" << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    SSL_CTX_set_default_passwd_cb(ctx_, OpenSSLWrapper::DTLSConnection::password_callback);


    // 检查私钥是否与证书匹配
    if (!SSL_CTX_check_private_key(ctx_)) {
        std::cout << "Private key does not match the certificate public key" << std::endl;
        return false;
    }

    return true;
}

bool OpenSSLWrapper::DTLSConnection::initializeSocket(const std::string& address, int port) {
    socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);  // 使用UDP进行DTLS通信
    if (socket_fd_ < 0) {
        std::cout << "Failed to create socket" << std::endl;
        return false;
    }

    

    if (type_ == SocketType::Server) {
        std::memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sin_family = AF_INET;
        target_addr.sin_addr.s_addr = inet_addr(address.c_str());
        target_addr.sin_port = htons(port);

        if (bind(socket_fd_, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            std::cout << "Failed to bind socket" << std::endl;
            return false;
        }
    }

    return true;
}

bool OpenSSLWrapper::DTLSConnection::connect(const std::string& address, int port) {
    if (!initializeSocket(address, port)) {
        return false;
    }
    // 初始化 SSLWrapper
    sslWrapper_ = std::make_unique<SSLWrapper>(ctx_);
    BIO *bio = BIO_new_dgram(socket_fd_, BIO_NOCLOSE);

    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &target_addr);
    sslWrapper_->setBIO(bio);

    int res = this->type_ == SocketType::Server ? sslWrapper_->accept(socket_fd_) : sslWrapper_->connect(socket_fd_);
    if (res){
        std::cout << (int)this->type_ << " " << sslWrapper_->get_error(res) << std::endl;
        std::cout << (int)this->type_ << " DTLS connection failed" << std::endl;
        sslWrapper_.reset();  // 失敗時釋放資源
        return false;
    }
    std::cout << (int)this->type_ << " DTLS connection succ" << std::endl;

    return true;
}

void OpenSSLWrapper::DTLSConnection::disconnect() {
    if (sslWrapper_) {
        sslWrapper_->shutdown();
        sslWrapper_.reset();  // 釋放資源
    }

    if (socket_fd_ != -1) {
        close(socket_fd_);
        socket_fd_ = -1;
    }
}

int OpenSSLWrapper::DTLSConnection::send(const char* data, int size) {
    if (sslWrapper_) {
        return sslWrapper_->write(data, size);
    }
    return -1;
}

int OpenSSLWrapper::DTLSConnection::receive(char* buffer, int size) {
    if (sslWrapper_) {
        return sslWrapper_->read(buffer, size);
    }
    return -1;
}
