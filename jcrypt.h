#ifndef JCRYPTER_JCRYPT_H
#define JCRYPTER_JCRYPT_H

#include <string>


class JCrypt{
    friend class JCryptTest;

public:
    int* toArray(std::string data);


};
#endif
