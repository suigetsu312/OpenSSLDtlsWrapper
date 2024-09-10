#include "BIOWrapper.hpp"
#include <cstring>  // For std::strlen

OpenSSLWrapper::BIOWrapper::BIOWrapper(BIO* bio) : bio_(bio) {
    // Ensure bio_ is valid or handle it appropriately
}

OpenSSLWrapper::BIOWrapper::~BIOWrapper() {
    // Free the BIO object when this wrapper is destroyed
    if(bio_)
        BIO_free(bio_);
}

int OpenSSLWrapper::BIOWrapper::read(char* buf, int size) {
    if (!bio_) {
        return -1;  // Error: BIO is not initialized
    }
    // Read data into buf from the BIO
    int len = BIO_read(bio_, buf, size);
    if (len <= 0) {
        // Optionally handle errors here
        return -1;  // Error or EOF
    }
    return len;  // Number of bytes read
}
BIO* OpenSSLWrapper::BIOWrapper::getBIO(){
    return bio_;
}
int OpenSSLWrapper::BIOWrapper::write(const char* buf, int size) {
    if (!bio_) {
        return -1;  // Error: BIO is not initialized
    }
    // Write data from buf to the BIO
    int len = BIO_write(bio_, buf, size);
    if (len <= 0) {
        // Optionally handle errors here
        return -1;  // Error
    }
    return len;  // Number of bytes written
}

int OpenSSLWrapper::BIOWrapper::puts(const char* buf) {
    if (!bio_) {
        return -1;  // Error: BIO is not initialized
    }
    // Write a string to the BIO, appending a newline
    int len = BIO_puts(bio_, buf);
    if (len <= 0) {
        // Optionally handle errors here
        return -1;  // Error
    }
    return len;  // Number of bytes written
}

int OpenSSLWrapper::BIOWrapper::gets(char* buf, int size) {
    if (!bio_) {
        return -1;  // Error: BIO is not initialized
    }
    // Read a line from the BIO into buf
    int len = BIO_gets(bio_, buf, size);
    if (len <= 0) {
        // Optionally handle errors here
        return -1;  // Error or EOF
    }
    return len;  // Number of bytes read
}
