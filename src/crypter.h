#include <stdint.h>
#include <string.h>

#include "test/test.h"

#ifndef CRYPTER_H
#define CRYPTER_H

#define BLOCK_SIZE 16
#define NUM_CRC_BYTES 4

class Crypter {
  friend class Tests;

  static uint32_t calculate_crc_32(uint8_t* crc_data, size_t crc_data_len);
  static void pack_crc_32(uint8_t* buffer, uint32_t crc, uint16_t position);
  static uint32_t unpack_crc_32(uint8_t* buffer, uint16_t position);
  static uint8_t* derive_key(char* passphrase);

public:
  // Assume data is passed in as a C-style string
  static uint8_t* ECB_encrypt(uint8_t* data, uint16_t *data_len, char* passphrase); // Returns data encrypted in place, length updated
  static uint8_t* ECB_decrypt(uint8_t* data, uint16_t* data_len, char* passphrase);

};
#endif
