#ifndef SAES_SAES_H
#define SAES_SAES_H

#include <string>
#include <array>
#include "lib/aes.h"

class SAES{
    // Allow test class access to private members
    friend class SAESTest;

    ~SAES();

    uint8_t* blocks; // not the best name for the intern data storage
    int size;
    uint8_t* iv;

    // Block is a buffer with size 16
    // Required for the encryption itself, but here it is just an abstraction
    int numblocks;


    void setiv();

    uint8_t* deriveKey(std::string key);

    void prefixIV();
    void extractIV();

    void clearInternalState();

    void blockify(std::string data);

public:
    // Public API
    void encryptText(std::string key, std::string data);
    void decryptText(std::string key, std::string data);



};
#endif
