#ifndef SAES_SAES_H
#define SAES_SAES_H

#include <string>
#include <array>
#include "lib/aes.h"

class SAES{
    friend class SAESTest;

    ~SAES();

    uint8_t* blocks; // not the best name for the intern data storage
    int size;
    uint8_t* iv;

    // Block is a buffer with size 16
    // Required for the encryption itself, but here it is just an abstraction
    int numblocks;


    void setiv();

    uint8_t* arrayKey(std::string key);

    void blockify(std::string data);

public:

    void encryptText(std::string key);
    void decryptText(std::string key);



};
#endif
