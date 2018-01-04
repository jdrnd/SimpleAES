#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <iostream>

// Enable EBC mode
#define ECB 1

#include "../lib/aes.h"
#include "test.h"


// prints string as hex
void Tests::phex(uint8_t* str)
{
    unsigned char i;
    for(i = 0; i < 16; ++i){
        printf("%.2x", str[i]);
    }
    std::cout<<"\n";
}

void Tests::runTests(void)
{
    std::cout<<"Beginning Tests\n\n";
    //test_encrypt_cbc();
    //test_decrypt_cbc();
    test_decrypt_ecb();
    test_encrypt_ecb();
    test_encrypt_ecb_verbose();
}
