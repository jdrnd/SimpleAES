#include "jcrypt.h"
#include <cmath>

JCrypt::~JCrypt() {
    delete[] blocks;
}

uint8_t* JCrypt::toArray(std::string data){
    uint8_t* bytearr = new uint8_t[data.size()];
    for (int i = 0; i< data.size(); i++){
        bytearr[i] = (uint8_t)data[i];
    }
    return bytearr;
}

void JCrypt::blockify(uint8_t *chars, int size) {
    //
    double numblocks = ceil(size / 16);

    blocks = new uint8_t*[(int)numblocks];

    for (int i = 0; i < (int)numblocks; i++ ){
        blocks[i] = new uint8_t[16];
        for (int j = 0; j < 16; j++){
            blocks[i][j] = chars[(i*16) + j];
        }
    }
}