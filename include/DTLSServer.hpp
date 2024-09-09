#ifndef OpenSSL_DTLS_SERVER
#define OpenSSL_DTLS_SERVER
#include "DTLSConnection.hpp"
#include "SSLWrapper.hpp"
#include <vector>
#include <memory>
#include <atomic>
namespace OpenSSLWrapper{
    class DTLSServer : public DTLSConnection {
        public:
        private:
            bool    server_accept();
            /// @brief <id, ssl>
            std::pair<int,std::unique_ptr<SSLWrapper>> ssl_list;
            std::pair<int,std::unique_ptr<sockaddr_in>> addr_list;
            std::atomic_int maximum_client_count = 5;
            std::atomic_int current_client_count = 0;
    };
}
#endif