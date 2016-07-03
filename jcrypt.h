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
    void encryptBuffer(std::string key);

public:



};
#endif
