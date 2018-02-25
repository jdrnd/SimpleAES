#include <assert.h>
#include <iostream>
#include <string.h>
#include <cstring>
#include <stdio.h>


#include "test.h"
#include "../crypter.h"


void Tests::test_crc(void) {
  std::cout << "CRC calculation: ";
  // Correct results verified against http://crccalc.com/

  uint8_t data[] = {(uint8_t)'t', (uint8_t)'e', (uint8_t)'s', (uint8_t)'t', (uint8_t)'\0'};
  uint32_t result = Crypter::calculate_crc_32(data, 4);
  assert(result == 0xD87F7E0C);

  result = Crypter::calculate_crc_32(data, 0);
  assert(result == 0x00);

  uint8_t longerdata[] = {0x6C, 0x6F, 0x6E, 0x67, 0x65, 0x72, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x77, 0x69, 0x74, 0x68, 0x6E, 0x75, 0x6D, 0x33, 0x72};
  result = Crypter::calculate_crc_32(longerdata, 28);
  assert(result == 0xCD2F0D8E);
  std::cout << "SUCCESS!\n";
}

void Tests::test_key_derivation(void) {
  std::cout << "Key derivation: ";
  uint8_t expected[] = {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10};
  uint8_t* key = Crypter::derive_key((char*)"");
  assert(!memcmp(key, expected, BLOCK_SIZE)); // correct comparision returns 0

  uint8_t expected2[] = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08};
  char pass[] = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '\0'};
  key = Crypter::derive_key(pass);
  assert(!memcmp(key, expected2, BLOCK_SIZE));
  std::cout << "SUCCESS!\n";
}
