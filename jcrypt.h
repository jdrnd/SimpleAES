#ifndef JCRYPTER_JCRYPT_H
#define JCRYPTER_JCRYPT_H

#include <string>
#include <array>

class JCrypt{
    friend class JCryptTest;

    ~JCrypt();

    uint8_t** blocks;

    void blockify(std::string data);

public:



};
#endif
