#include <stdio.h>
#include <stdint.h>
#include <iostream>

// Enable EBC mode
#define ECB 1

#include "../lib/aes.h"
#include "test.h"


// prints string as hex
void Tests::phex(uint8_t* str)
{
    uint8_t i;
    for(i = 0; i < BLOCK_SIZE; ++i){
        printf("%.2x", str[i]);
    }
    std::cout<<"\n";
}

void Tests::runTests(void)
{
    std::cout<<"Beginning Tests\n\n";
    /*
    test_decrypt_ecb();
    test_encrypt_ecb();
    test_encrypt_ecb_verbose();
    test_crc();
    test_key_derivation();
    test_ecb();*/
    test_cbc();
}
