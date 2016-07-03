#ifndef JCRYPTER_JCRYPT_H
#define JCRYPTER_JCRYPT_H

#include <string>
#include <array>
#include "lib/aes.h"

class JCrypt{
    friend class JCryptTest;

    ~JCrypt();

    uint8_t** blocks;
    int numblocks;

    void blockify(std::string data);

    uint8_t* arrayKey(std::string key);

    void encrypt(std::string key);
    void decrypt(std::string key);

    uint8_t* blocks2;
    int size;

    void blockify2(std::string data);
    void encrpyt2(std::string key);
    void decrypt2(std::string key);

public:



};
#endif
