#include "DTLSConnection.hpp"
#include "DTLSServer.hpp"
#include "DTLSClient.hpp"
#include "UtilCallbacks.hpp"
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
OpenSSLWrapper::DTLSConnection::DTLSConnection(SocketType type, const std::string& ca)
    : certFile_(""), keyFile_(""), ca_(ca), 
              ctx_(nullptr), socket_fd_(-1), target_addr{}, type_(type) {
    // 初始化 SSL
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    // 初始化 DTLS 连接所需的 SSL_CTX
    ctx_ = SSL_CTX_new(type_ == SocketType::Server ? DTLS_server_method() : DTLS_client_method());
    if (!ctx_) {
        std::cout << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        return;
    }
    setCA(ca);

}

OpenSSLWrapper::DTLSConnection::DTLSConnection(SocketType type, const std::string& certFile, 
                const std::string& keyFile)
            : certFile_(certFile), keyFile_(keyFile), ca_(""), 
              ctx_(nullptr), socket_fd_(-1), target_addr{} {
    // 初始化 SSL
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    // 初始化 DTLS 连接所需的 SSL_CTX
    ctx_ = SSL_CTX_new(type_ == SocketType::Server ? DTLS_server_method() : DTLS_client_method());
    if (!ctx_) {
        std::cout << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        return;
    }
    setCertificate(certFile, keyFile);

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

bool OpenSSLWrapper::DTLSConnection::ctxInit()
{
    // 初始化 DTLS 连接所需的 SSL_CTX
    if (typeid(*this) == typeid(DTLSServer)) {
        ctx_ = SSL_CTX_new(DTLS_server_method());
    }
    else if (typeid(*this) == typeid(DTLSClient)) {
        ctx_ = SSL_CTX_new(DTLS_client_method());
    }   
    else{
        std::cout << "OpenSSLWrapper::DTLSConnection::ctxInit error : can't identify this instance is client or server" << std::endl;
        return false;
    }

    if (!ctx_) {
        std::cout << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
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
    //SSL_CTX_set_default_passwd_cb(ctx_, OpenSSLWrapper::password_callback);


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

    std::memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_addr.s_addr = inet_addr(address.c_str());
    target_addr.sin_port = htons(port);

    int opt = 1;
    if (setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) 
    {
        std::cout << "Failed to set reuseaddr" << std::endl;
        return false;
    }


    if (type_ == SocketType::Server) {

        if (::bind(socket_fd_, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            std::cout << "Failed to bind socket" << std::endl;
            return false;
        }
    }
    
    if (type_ == SocketType::Client) {

        if (::connect(socket_fd_, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            std::cout << "Failed to connect socket" << std::endl;
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
    bool res = (type_ == SocketType::Server) ? server_accept() : client_connect();
    
    connected = res;
    
    return res;
}
bool OpenSSLWrapper::DTLSConnection::server_accept(){
    BIO *bio = BIO_new_dgram(socket_fd_, BIO_NOCLOSE);
    sslWrapper_->setBIO(bio);
    struct timeval timeout;
    timeout.tv_sec = 5;  // 設置 3 秒超時
    timeout.tv_usec = 0;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, &target_addr);
    std::lock_guard<std::mutex> guard(conn_mutex);
    bool res = sslWrapper_->accept(socket_fd_);
    if (!res){
        std::cout << (int)this->type_ << "Server Side Handshark failed";
        std::cout << " Openssl Error Code : " << sslWrapper_->get_error(res) << std::endl;
        sslWrapper_.reset();  // 失敗時釋放資源
        return false;
    }
    std::cout << (int)this->type_ << "Server Side Handshark Success"<< std::endl;
    
    return true;
}

bool OpenSSLWrapper::DTLSConnection::client_connect(){

    BIO *bio = BIO_new_dgram(socket_fd_, BIO_NOCLOSE);
    struct timeval timeout;
    timeout.tv_sec = 5;  // 設置 3 秒超時
    timeout.tv_usec = 0;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, &target_addr);
    sslWrapper_->setBIO(bio);
    std::lock_guard<std::mutex> guard(conn_mutex);
    bool res = sslWrapper_->connect(socket_fd_);;
    if (!res){
        std::cout << (int)this->type_ << "Client Side Handshark failed";
        std::cout << " Openssl Error Code : " << sslWrapper_->get_error(res) << std::endl;
        sslWrapper_.reset();  // 失敗時釋放資源
        return false;
    }
    std::cout << (int)this->type_ << "Client Side Handshark Success"<< std::endl;
    return true;
}

void OpenSSLWrapper::DTLSConnection::disconnect() {
    std::lock_guard<std::mutex> guard(conn_mutex);
    if(!connected){return;}
    connected = false;
    
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
    if (connected&& sslWrapper_) {
        int err = sslWrapper_->write(data, size);

        if (err == SSL_ERROR_WANT_READ) {
            // 这里可以使用 select() 或 poll() 等待数据到达
            std::cerr << "SSL_read wants more data, try again later" << std::endl;
            return 0;
        }
        return err;
    }
    return -1;
}

int OpenSSLWrapper::DTLSConnection::receive(char* buffer, int size) {
    if (connected&& sslWrapper_) {
        int err = sslWrapper_->read(buffer, size);
        if (err == SSL_ERROR_WANT_WRITE) {
            // 这里可以使用 select() 或 poll() 等待数据到达
            std::cerr << "SSL_read wants more data, try again later" << std::endl;
            return 0;
        }
        return err;
    }
    return -1;
}
