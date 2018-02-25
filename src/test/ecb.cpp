#include <stdint.h>
#include <iostream>
#include <cassert>

#include "test.h"
#include "../lib/aes.h"
#include "../crypter.h"

void Tests::test_ecb(void) {
  uint8_t* data = NULL;
  uint16_t* data_len = new uint16_t(0);

  Crypter::ECB_encrypt(data, data_len, NULL);
  Crypter::ECB_decrypt(data, data_len, NULL);

  uint8_t* short_data = new uint8_t[4];
  for (int i = 0; i<4; i++) {
    short_data[i] = 0xFF;
  }

  *data_len = 4;
  short_data = Crypter::ECB_encrypt(short_data, data_len, NULL);
  short_data = Crypter::ECB_decrypt(short_data, data_len, NULL);

  assert(*data_len == 4);
  uint8_t original[] = {0xFF, 0xFF, 0xFF, 0xFF};
  assert(0 == strncmp((char*)short_data, (char*)original, 4));
}
