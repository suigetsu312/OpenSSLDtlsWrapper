#ifndef OpenSSLWrapper_callbacks
#define OpenSSLWrapper_callbacks

#include <iostream>
#include <cstring>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#define SSL_WHERE_INFO(ssl, w, flag, msg) {                \
    if(w & flag) {                                         \
      printf("+ %s: ", name);                              \
      printf("%20.20s", msg);                              \
      printf(" - %30.30s ", SSL_state_string_long(ssl));   \
      printf(" - %5.10s ", SSL_state_string(ssl));         \
      printf("\n");                                        \
    }                                                      \
  } 
typedef void(*info_callback)();

namespace OpenSSLWrapper{
    static int password_callback(char *buf, int size, int rwflag, void *userdata) {
        const char *password = "3263"; // 這裡替換成你的密碼
        strncpy(buf, password, size);
        buf[size - 1] = '\0';
        return strlen(buf);
    }
//void (*cb)(const SSL *ssl, int type, int val))
    static void ssl_info_callback(const SSL* ssl, int where, int ret) {
 
        const char *str;
        int w;

        w=where& ~SSL_ST_MASK;

        if (w & SSL_ST_CONNECT) str="SSL_connect";
        else if (w & SSL_ST_ACCEPT) str="SSL_accept";
        else str="undefined";

        if (where & SSL_CB_LOOP)
                {
                printf("%s:%s\n",str,SSL_state_string_long(ssl));
                }
        else if (where & SSL_CB_ALERT)
        {
        str=(where & SSL_CB_READ)?"read":"write";
                printf("SSL3 alert %s:%s:%s\n",
                str,
                SSL_alert_type_string_long(ret),
                SSL_alert_desc_string_long(ret));
        }
        else if (where & SSL_CB_EXIT)
        {
            if (ret == 0)
                printf("%s:failed in %s\n",
                        str,SSL_state_string_long(ssl));
            else if (ret < 0)
            {
                printf("%s:error in %s\n",
                        str,SSL_state_string_long(ssl));
            }
        }
        else if (where & SSL_CB_HANDSHAKE_START)
        {
            printf("SSL_CB_HANDSHAKE_START \n");
            printf("%s:error in %s\n",str,SSL_state_string_long(ssl));
        }
        else if (where & SSL_CB_HANDSHAKE_DONE)
        {
            printf("SSL_CB_HANDSHAKE_DONE \n");
            printf("%s:error in %s\n",str,SSL_state_string_long(ssl));
        }
    }
}

#endif // DEBUG

