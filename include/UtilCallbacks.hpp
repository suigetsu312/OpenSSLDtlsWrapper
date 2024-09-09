#ifndef OpenSSLWrapper_callbacks
#define OpenSSLWrapper_callbacks

#include <iostream>
#include <cstring>

namespace OpenSSLWrapper{
    static int password_callback(char *buf, int size, int rwflag, void *userdata) {
        const char *password = "3263"; // 這裡替換成你的密碼
        strncpy(buf, password, size);
        buf[size - 1] = '\0';
        return strlen(buf);
    }
}

#endif // DEBUG

