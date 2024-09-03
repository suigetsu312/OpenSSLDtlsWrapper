#ifndef OpenSSL_DTLSCONNECTION
#define OpenSSL_DTLSCONNECTION
#include <SSLWrapper.hpp>
#include <SocketType.hpp>
#include<netinet/in.h>
#include <memory>
namespace OpenSSLWrapper{
    class DTLSConnection {
    public:
        DTLSConnection(SocketType type);
        ~DTLSConnection();

        bool setCertificate(const std::string& certFile, const std::string& keyFile);
        bool connect(const std::string& address, int port);
        void disconnect();
        int send(const char* data, int size);
        int receive(char* buffer, int size);
        

    private:
        bool initializeSocket(const std::string& address, int port);
        bool initializeSSL();
        std::unique_ptr<SSLWrapper> sslWrapper_;
        SSL_CTX* ctx_;
        int socket_fd_;
        SocketType type_;
        struct sockaddr_in target_addr;
        static int password_callback(char *buf, int size, int rwflag, void *userdata) {
            const char *password = "3263"; // 這裡替換成你的密碼
            strncpy(buf, password, size);
            buf[size - 1] = '\0';
            return strlen(buf);
        }

    };
}



#endif