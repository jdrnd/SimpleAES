#include <cstdint>
#include <iostream>
#include <cassert>

#include "test.h"
#include "../lib/aes.h"
#include "../src/crypter.h"

void Tests::test_ecb(void) {
    uint8_t *data = nullptr;
    uint32_t *data_len = new uint32_t(0);

    Crypter::ECB_encrypt(data, data_len, nullptr);
    Crypter::ECB_decrypt(data, data_len, nullptr);

  // Input data must be a pointer so that we can write new data to it later
    auto *short_data = new uint8_t[4];
  for (int i = 0; i<4; i++) {
    short_data[i] = 0xFF;
  }

  *data_len = 4;
    short_data = Crypter::ECB_encrypt(short_data, data_len, nullptr);
    short_data = Crypter::ECB_decrypt(short_data, data_len, nullptr);

  assert(*data_len == 4);
  uint8_t original[] = {0xFF, 0xFF, 0xFF, 0xFF};
  assert(0 == strncmp((char*)short_data, (char*)original, 4));
}
