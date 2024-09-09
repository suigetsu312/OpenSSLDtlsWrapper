#ifndef OpenSSL_DTLS_CLIENT
#define OpenSSL_DTLS_CLIENT
#include "DTLSConnection.hpp"

namespace OpenSSLWrapper{
    class DTLSClient : public DTLSConnection{
        public:
            DTLSClient(std::string& ca);
        private:
            bool client_connect();
            std::unique_ptr<SSLWrapper> ssl;
    };
}
#endif