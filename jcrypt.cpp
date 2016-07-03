#include "jcrypt.h"
#include <cmath>
#include <iostream>
#include "lib/aes.h"
#include "lib/aes.cpp"

JCrypt::~JCrypt(){
    delete[] blocks;
}

void JCrypt::blockify(std::string data) {

    double num = ceil((double)data.size() / 16);
    numblocks = (int)num;

    int size = data.size();

    // Create blocks to fill data into
    blocks = new uint8_t*[numblocks];

    for (int i = 0; i < numblocks; i++ ){

        blocks[i] = new uint8_t[16];

        for (int j = 0; j < 16; j++){
            if ( ((16*i) + j) < size){
                blocks[i][j] = (uint8_t)data[(16*i) + j];
            }
            else{
                blocks[i][j] = 0;
            }

        }
    }
}

uint8_t* JCrypt::arrayKey(std::string key){
    uint8_t* keyarr = new uint8_t[key.length() - 1];

    for (int i = 0; i < key.length(); i++){
        keyarr[i] = (uint8_t)key[i];
    }
    return keyarr;
}

void JCrypt::encryptBuffer(std::string key){

    const uint8_t* keyarr = arrayKey(key);
    uint8_t** output = new uint8_t*[numblocks];

    for (int i = 0; i<numblocks; i++){
        output[i] = new uint8_t[16];
    }

    for (int i = 0; i < numblocks; i++){
        AES128_ECB_encrypt(blocks[i], keyarr, output[i]);
    }

    // Remove plaintext and swap for cyphertext
    delete[] blocks;
    blocks = output;
}