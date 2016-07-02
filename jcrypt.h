#ifndef JCRYPTER_JCRYPT_H
#define JCRYPTER_JCRYPT_H

#include <string>
#include <array>

class JCrypt{
    friend class JCryptTest;

    ~JCrypt();

    uint8_t** blocks;

    uint8_t* toArray(std::string data);
    void blockify(uint8_t* chars, int size);

public:



};
#endif
