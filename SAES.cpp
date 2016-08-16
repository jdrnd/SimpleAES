#include "SAES.h"
#include <cmath>
#include <iostream>
#include "lib/aes.h"
#include "lib/aes.cpp"
#include <cstdlib>
#include <time.h>

SAES::~SAES() {
    delete[] blocks;
    delete iv;
}


// Transforms an arbitrary string into an character array
// With length being an exact multiple of 16
// Pads with extra zeros if required
void SAES::blockify(std::string data){

    uint8_t* keyarr = new uint8_t[data.length() - 1];

    double num = ceil((double)data.size() / 16);
    numblocks = (int)num;
    size = 16*numblocks;

    uint8_t* iv = new uint8_t[16];

    for (int i = 0; i<16; i++){
        iv[i] = (uint8_t)'a';
    }

    const uint8_t* iv2 = iv;

    blocks = new uint8_t[size];

    for (int i = 0; i < size; i++){
        if (i < data.length()){
            blocks[i] = (uint8_t)data[i];
        }
        else{
            blocks[i] = 0;
        }
    }
}

// Key derivation algorithm:
// Currently: Transforms an arbitrary key into a 16-length byte array
// Pads key with extra zeros if required
// TODO look into how to do proper key derivation (ie hashing, ect)
uint8_t* SAES::deriveKey(std::string key){
    uint8_t* keyarr = new uint8_t[16];


    for (int i = 0; i < 16; i++){
        if (i < key.length()){
            keyarr[i] = (uint8_t)key[i];
        }
        else {
            keyarr[i] = 0;
        }
    }

    return keyarr;
}

// Creates a pseudorandom 16 byte buffer to be used as the initialization vector
void SAES::setiv(){

    // Seed the PRNG
    // NOT SECURE! USES POOR RNG
    srand(time(NULL));

    // Attempt to clear an existing IV
    try{
        delete[] iv;
        iv = NULL;
    }
    catch (int e){}

    // Allocate a new buffer and fill it with data
    iv = new uint8_t[16];
    for (int i = 0; i< 16; i++){
        iv[i] = (uint8_t)(rand() % 256);
    }
}

// Clears internal object data after an encrypt or decrypt operation
void SAES::clearInternalState() {
    delete blocks;
    delete iv;
    blocks = NULL;
    iv = NULL;

    size = 0;
    numblocks = 0;
}


// Extracts the prefixed IV from a buffer of data
// ie. separates data into the first 16 bytes (IV), and actual data (the rest)
// Used for decrypting stored data
void SAES::extractIV() {

    // Assumed first 16 bytes of buffer store the initialization vector used
    iv = new uint8_t[16];

    // Declared outside so both looks can use it
    int i = 0;
    // Copy first 16 bytes into IV
    for (i = 0; i < 16; i++){
        iv[i] = blocks[i];
    }
    //Copy rest of data into new buffer with out IV;
    uint8_t* oldblocks = blocks;

    blocks = new uint8_t[16 * (numblocks)];
    for (int i = 16; i < (numblocks*16); i++){
        blocks[i-16] = oldblocks[i];
    }
    delete oldblocks;

}

// Prefixes IV to stored data as first 16 bytes
// Designed so data can be decrypted at a later time
void SAES::prefixIV() {

    uint8_t* oldblocks = blocks;
    blocks = new uint8_t[16*(numblocks + 1)];

    // Use i in function scope so both loops can use it
    // Add IV data to new buffer
    int i = 0;
    for (i; i<16; i++){
        blocks[i] = iv[i];
    }
    for(i; i < 16*(numblocks + 1); i++){
        blocks[i] = oldblocks[i-16];
    }
    delete oldblocks;
}

// Public interface method below:


// TODO these funcions need to return something....
void SAES::encryptText(std::string key, std::string data) {

    // Key most be const as per underlying implimentation's requirements
    const uint8_t* keyarr = deriveKey(key);

    // Transform data into int vals, store in buffer
    blockify(data);

    AES128_CBC_encrypt_buffer16_ip(blocks, (uint8_t)size, keyarr, iv);
    prefixIV();

    delete keyarr;
    keyarr = NULL;
    clearInternalState();

}

void SAES::decryptText(std::string key, std::string data) {

    const uint8_t* keyarr = deriveKey(key);
    blockify(data);
    extractIV();
    AES128_CBC_decrypt_buffer16_ip(blocks, (uint8_t)size, keyarr, iv);

    delete keyarr;
    keyarr = NULL;
    clearInternalState();
}