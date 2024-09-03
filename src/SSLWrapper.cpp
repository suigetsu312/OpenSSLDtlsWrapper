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

bool OpenSSLWrapper::SSLWrapper::connect(int socket_fd){
    std::lock_guard<std::mutex> guard(ssl_mutex_);
    if (!ssl_) return false;
    SSL_set_connect_state(ssl_);
    SSL_set_fd(ssl_, socket_fd);

    if (SSL_connect(ssl_) <= 0) {
        std::cout << "SSL connection failed" << std::endl;
        ERR_print_errors_fp(stdout);
        return false;
    }
    return true;
}

bool OpenSSLWrapper::SSLWrapper::accept(int socket_fd){
    std::lock_guard<std::mutex> guard(ssl_mutex_);
    if (!ssl_) return false;
    SSL_set_accept_state(ssl_);
    SSL_set_fd(ssl_, socket_fd);

    if (SSL_accept(ssl_) <= 0) {
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
    std::lock_guard<std::mutex> guard(ssl_mutex_);
    if (!ssl_) return -1;

    return SSL_write(ssl_, buffer, size);
}
void OpenSSLWrapper::SSLWrapper::shutdown(){
    std::lock_guard<std::mutex> guard(ssl_mutex_);
    if (ssl_) {
        SSL_shutdown(ssl_);
    }
}

void OpenSSLWrapper::SSLWrapper::setBIO(BIO* bio){
    SSL_set_bio(ssl_, bio, bio);
}

int OpenSSLWrapper::SSLWrapper::get_error(int error){
    return SSL_get_error(ssl_, error);
}
