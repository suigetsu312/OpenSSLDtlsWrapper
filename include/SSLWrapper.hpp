#ifndef OpenSSL_SSLWrapper
#define OpenSSL_SSLWrapper


#include <openssl/ssl.h>
#include <openssl/err.h>
#include <mutex>
#include <iostream>
namespace OpenSSLWrapper{

    class SSLWrapper{
    public:
        SSLWrapper(SSL_CTX* ctx);
        ~SSLWrapper();

        // 禁止拷貝和賦值操作
        SSLWrapper(const SSLWrapper&) = delete;
        SSLWrapper& operator=(const SSLWrapper&) = delete;

        // 禁止移動操作
        SSLWrapper(SSLWrapper&&) = delete;
        SSLWrapper& operator=(SSLWrapper&&) = delete;

        bool connect(int socket_fd);
        bool accept(int socket_fd);
        int read(char* buffer, int size);
        int write(const char* buffer, int size);
        void shutdown();
        void setBIO(BIO* bio);
        int get_error(int error);
    private:
        SSL* ssl_;
        std::mutex ssl_mutex_;
    };
}
#endif // DTLS_SERVER_HPP
