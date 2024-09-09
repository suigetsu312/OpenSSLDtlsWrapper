#include "SSLWrapper.hpp"
OpenSSLWrapper::SSLWrapper::SSLWrapper(SSL_CTX* ctx){
    ssl_ = SSL_new(ctx);
    if (!ssl_) {
        std::cout << "Unable to create SSL object" << std::endl;
        ERR_print_errors_fp(stdout);
    }
};
OpenSSLWrapper::SSLWrapper::~SSLWrapper(){
    std::lock_guard<std::mutex> guard(ssl_mutex_);
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
    }
}

OpenSSLWrapper::SSLWrapper::SSLWrapper(OpenSSLWrapper::SSLWrapper && other){
    ssl_ = other.ssl_;
    other.ssl_ = nullptr;
}

OpenSSLWrapper::SSLWrapper& OpenSSLWrapper::SSLWrapper::operator=(OpenSSLWrapper::SSLWrapper&& other){
    if (this != &other) { // 防止自我赋值
        std::lock_guard<std::mutex> guard(ssl_mutex_);
        ssl_ = other.ssl_;
        other.ssl_ = nullptr;
    }
    return *this;
}

bool OpenSSLWrapper::SSLWrapper::connect(int socket_fd){
    std::lock_guard<std::mutex> guard(ssl_mutex_);
    if (!ssl_) return false;
    int ret = SSL_connect(ssl_);
    if (ret <= 0) {
        std::cout << "SSL connection failed" << std::endl;
        ERR_print_errors_fp(stdout);
        return false;
    }
    return true;
}

bool OpenSSLWrapper::SSLWrapper::accept(int socket_fd){
    std::lock_guard<std::mutex> guard(ssl_mutex_);
    if (!ssl_) return false;
    int ret = SSL_accept(ssl_);
    if (ret <= 0) {
        std::cout << "SERVER SSL accept failed" << std::endl;
        ERR_print_errors_fp(stdout);   
        return false;
    }
    return true;
}


int OpenSSLWrapper::SSLWrapper::read(char* buffer, int size){
    std::lock_guard<std::mutex> guard(ssl_mutex_);
    if (!ssl_) return -1;

    return SSL_read(ssl_, buffer, size);

}
int OpenSSLWrapper::SSLWrapper::write(const char* buffer, int size){
    if (!ssl_) return -1;

    return SSL_write(ssl_, buffer, size);
}
void OpenSSLWrapper::SSLWrapper::shutdown(){
    if (ssl_) {
        SSL_shutdown(ssl_);
    }
}

void OpenSSLWrapper::SSLWrapper::setBIO(BIO* bio){
    std::lock_guard<std::mutex> guard(ssl_mutex_);
    if(ssl_){
        SSL_set_bio(ssl_, bio, bio);
    }
}

int OpenSSLWrapper::SSLWrapper::get_error(int error){
    std::lock_guard<std::mutex> guard(ssl_mutex_);
    if(!ssl_) return -1;
    return SSL_get_error(ssl_, error);
}
