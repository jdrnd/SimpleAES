#ifndef JCRYPTER_JCRYPT_H
#define JCRYPTER_JCRYPT_H

#include <string>
#include <array>
#include "lib/aes.h"

class JCrypt{
    friend class JCryptTest;

    ~JCrypt();

    uint8_t* blocks;
    int size;
    uint8_t* iv;

    int numblocks;


    void setiv();

    uint8_t* arrayKey(std::string key);

    void encrypt(std::string key);
    void decrypt(std::string key);



    void blockify(std::string data);

public:




};
#endif
