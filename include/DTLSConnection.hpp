#ifndef OpenSSL_DTLSCONNECTION
#define OpenSSL_DTLSCONNECTION
#include <SSLWrapper.hpp>
#include <SocketType.hpp>
#include <netinet/in.h>
#include <DTLSConnectOption.hpp>
#include <BIOWrapper.hpp>

#include <memory>
namespace OpenSSLWrapper{
    class DTLSConnection {

    public:
        DTLSConnection(const std::string& certFile, 
                       const std::string& keyFile,
                       const std::string& ca = nullptr );

        DTLSConnection(const std::string& certFile, 
                const std::string& keyFile);

        DTLSConnection(const std::string& ca);
        DTLSConnection(SocketType type, const std::string& ca);
        DTLSConnection(SocketType type, const std::string& certFile, 
                       const std::string& keyFile);
        ~DTLSConnection();
        bool    connect(ConnectOption option);
        bool    connect(const std::string& address, int port);
        bool    disconnect(DisConnectOption option);
        bool    setBIO(BIO* wbio,BIO* rbio);

        void    disconnect();
        int     send(const char* data, int size);
        int     receive(char* buffer, int size);
        bool    connected = false;

    protected:
        bool    initializeSocket(const std::string& address, int port);
        bool    initializeSSL();
        bool    setCertificate(const std::string& certFile, 
                                const std::string& keyFile);
        bool    setCA(const std::string& ca);
        bool    ctxInit();
        bool    client_connect();
        bool    server_accept();

        SSL_CTX* ctx_;
        int socket_fd_;
        std::mutex conn_mutex;
        struct sockaddr_in target_addr;
        const std::string& certFile_;
        const std::string& keyFile_;
        const std::string& ca_;
        SocketType type_;
        std::unique_ptr<SSLWrapper> sslWrapper_;
        std::unique_ptr<BIOWrapper> wbio_;
        std::unique_ptr<BIOWrapper> rbio_;

    };
}
#endif