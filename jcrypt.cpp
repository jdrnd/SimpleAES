#include "jcrypt.h"
#include <cmath>
#include <iostream>

JCrypt::~JCrypt(){
    delete[] blocks;
}

void JCrypt::blockify(std::string data) {

    double num = ceil((double)data.size() / 16);
    int size = data.size();

    // Create blocks to fill data into
    blocks = new uint8_t*[(int)num];

    for (int i = 0; i < (int)num; i++ ){

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