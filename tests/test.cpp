#include <cstdio>
#include <cstdint>
#include <iostream>

// Enable EBC mode
#define ECB 1

#include "../lib/aes.h"
#include "test.h"



void Tests::runTests(void)
{
    std::cout<<"Beginning Tests\n\n";
    test_decrypt_ecb();
    test_encrypt_ecb();
    test_encrypt_ecb_verbose();
    test_crc();
    test_key_derivation();
    test_ecb();
    test_cbc();
    test_pcbc();
    test_cfb();
    std::cout << "All Tests Passed\n";
}
