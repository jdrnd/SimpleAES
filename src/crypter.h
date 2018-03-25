#include <stdint.h>
#include <string.h>

#include "../test/test.h"

#ifndef CRYPTER_H
#define CRYPTER_H

#define BLOCK_SIZE 16
#define NUM_CRC_BYTES 4

// 32 bit CRC polynomial from the ethenet standard
#define CRC_POLY 0xEDB88320
#define CRC_LEN 4

#define DEBUG

class Crypter {
  friend class Tests;

  // Utils
  static uint32_t calculate_crc_32(uint8_t* crc_data, size_t crc_data_len);
  static void pack_crc_32(uint8_t* buffer, uint32_t crc, uint32_t position);
  static uint32_t unpack_crc_32(uint8_t* buffer, uint32_t position);
  static uint8_t* derive_key(char* passphrase);
  static void generate_and_fill_IV(uint8_t* data_buffer);

  // Helpers
  static size_t calculate_num_blocks(size_t* data_len);
  static uint8_t calculate_padding_len(size_t* data_len, size_t num_blocks);
  static void xor_together(uint8_t* block1, uint8_t* block2);


public:
  Crypter();

  // Assume data is passed in as a C-style string
  static uint8_t* ECB_encrypt(uint8_t* data, size_t *data_len, char* passphrase); // Returns data encrypted in place, length updated
  static uint8_t* ECB_decrypt(uint8_t* data, size_t* data_len, char* passphrase);

  static uint8_t* CBC_encrypt(uint8_t* data, size_t *data_len, char* passphrase); // Returns data encrypted in place, length updated
  static uint8_t* CBC_decrypt(uint8_t* data, size_t* data_len, char* passphrase);

};
#endif
