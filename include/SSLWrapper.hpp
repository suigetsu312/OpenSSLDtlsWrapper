#ifndef OpenSSL_SSLWrapper
#define OpenSSL_SSLWrapper


#include <openssl/ssl.h>
#include <openssl/err.h>
#include <mutex>
#include <iostream>
namespace OpenSSLWrapper{

    static void GetError(int error){
        switch (error) {
            case SSL_ERROR_NONE:
                // No error, but no data sent
                break;
            case SSL_ERROR_ZERO_RETURN:
                std::cout << "Connection closed" << std::endl;
                break;
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                // Operation should be retried later
                std::cout << "Operation should be retried later" << std::endl;
                break;
            case SSL_ERROR_SYSCALL:
                std::cout << "System call error" << std::endl;
                break;
            case SSL_ERROR_SSL:
                std::cout << "SSL protocol error" << std::endl;
                ERR_print_errors_fp(stdout);
                break;
            default:
                std::cout << "Unknown error" << std::endl;
                break;
        }

    }

    class SSLWrapper{
    public:
        SSLWrapper(SSL_CTX* ctx);
        ~SSLWrapper();
        SSLWrapper(SSLWrapper&& other);

        // 禁止拷貝和賦值操作
        SSLWrapper(const SSLWrapper&) = delete;

        bool connect(int socket_fd);
        bool accept(int socket_fd);
        int read(char* buffer, int size);
        int write(const char* buffer, int size);
        void shutdown();
        void setBIO(BIO* bio);
        int get_error(int error);

        SSLWrapper& operator=(SSLWrapper&& other);
    private:
        SSL* ssl_;
        std::mutex ssl_mutex_;
    };
}
#endif // DTLS_SERVER_HPP
