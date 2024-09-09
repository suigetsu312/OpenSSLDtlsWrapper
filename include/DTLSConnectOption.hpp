#ifndef OpenSSL_DTLSCONNECTIONOPTION
#define OpenSSL_DTLSCONNECTIONOPTION
#include<netinet/in.h>
#include <string>

namespace OpenSSLWrapper{

    struct ConnectOption
    {
        /* data */
        struct sockaddr_in target_addr;
    };

    struct DisConnectOption
    {
        /* data */
        int ClientID =0;
    };

    struct SendOption
    {
        /* data */
        int ClientID =0;
        std::string content;
    };

}


#endif
