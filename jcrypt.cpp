#include <cmath>
#include <iostream>
#include "lib/aes.h"
#include "lib/aes.cpp"

uint8_t* keyToArray(std::string key){
    int size = key.length();
    uint8_t* keyarr = new uint8_t[size];

    for (int i = 0; i<size; i++){
        keyarr[i] = (uint8_t)key[i];
    }
    return keyarr;
}
void printArray(uint8_t* array, int size){
    for (int i = 0; i< size; i++){
        std::cout << (int)array[i] << " ";
    }
}

uint8_t* blockify(std::string data){

    double num = ceil((double)data.size() / 16);
    int numblocks = (int)num;
    int size = 16*numblocks;


    uint8_t* blocks = new uint8_t[size];

    for (int i = 0; i < size; i++){
        if (i < data.length()){
            blocks[i] = (uint8_t)data[i];
        }
        else{
            blocks[i] = 0;
        }

    }
    printArray(blocks, size);
    return blocks;
}

uint8_t* arrayKey(std::string key){
    uint8_t* keyarr = new uint8_t[key.length() - 1];

    for (int i = 0; i < key.length(); i++){
        keyarr[i] = (uint8_t)key[i];
    }
    return keyarr;
}

void encrypt(std::string key, uint8_t* data){
    const uint8_t* keyarr = keyToArray(key);
    const uint32_t length = 16;

    const uint8_t* iv = new uint8_t((uint8_t)985);

    AES128_CBC_encrypt_buffer16_ip(data, length, keyarr, iv);
}

void decrypt(std::string key, uint8_t* data){
    const uint8_t* keyarr = keyToArray(key);
    const uint32_t length = 16;

    const uint8_t* iv = new uint8_t((uint8_t)985);

    AES128_CBC_decrypt_buffer16_ip(data, length, keyarr, iv);
}
int main(){

    uint8_t data[16] = {12,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    printArray(data, 16);
    std::cout << "\n\n";

    encrypt("test", data);
    printArray(data, 16);
    std::cout << "\n\n";

    decrypt("test", data);
    printArray(data, 16);



}
