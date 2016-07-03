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

void JCrypt::blockify2(std::string data){

    uint8_t* keyarr = new uint8_t[data.length() - 1];

    double num = ceil((double)data.size() / 16);
    numblocks = (int)num;
    size = 16*numblocks;

    const uint8_t* iv = new uint8_t(1900);

    blocks2 = new uint8_t[size];

    for (int i = 0; i < size; i++){
        if (i < data.length()){
            blocks2[i] = (uint8_t)data[i];
        }
        else{
            blocks2[i] = 0;
        }

    }

    AES128_CBC_encrypt_buffer16_ip(blocks2, size, keyarr, iv);
}

uint8_t* JCrypt::arrayKey(std::string key){
    uint8_t* keyarr = new uint8_t[key.length() - 1];

    for (int i = 0; i < key.length(); i++){
        keyarr[i] = (uint8_t)key[i];
    }
    return keyarr;
}

void JCrypt::encrypt(std::string key){

    const uint8_t* keyarr = arrayKey(key);
    const uint8_t* iv = new uint8_t(1900);

    for (int i = 0; i < numblocks; i++){
        AES128_CBC_encrypt_buffer16_ip(blocks[i], 16, keyarr, iv);
    }
}

void JCrypt::decrypt(std::string key) {

    const uint8_t* keyarr = arrayKey(key);
    const uint8_t* iv = new uint8_t(1900);

    for (int i = 0; i < numblocks; i++){
        AES128_CBC_decrypt_buffer16_ip(blocks[i], 16, keyarr, iv);
    }
}
