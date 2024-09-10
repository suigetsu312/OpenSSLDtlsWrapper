#ifndef OPENSSLWRAPPER_BIOWRAPPER
#define OPENSSLWRAPPER_BIOWRAPPER

#include <openssl/ssl.h>

namespace OpenSSLWrapper
{
    class BIOWrapper {
    public:
        BIOWrapper(BIO* bio);
        ~BIOWrapper();

        int read(char* buf, int size);
        int write(const char* buf, int size);
        int puts(const char* buf);
        int gets(char* buf, int size);
        BIO* getBIO();
    private:
        BIO* bio_;
    };
}
#endif // !OPENSSLWRAPPER_BIOWRAPPER

