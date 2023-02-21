#ifndef CRYPTER_H
#define CRYPTER_H

#include <cstdint>
#include <cstring>
#include <vector>

#include "types.h"
#include "key.hpp"

#include "absl/types/span.h"

using absl::Span;

class Crypter {

  // Utils
  static uint32_t calculate_crc_32(uint8_t *crc_data, uint32_t crc_data_len);
  static uint32_t calculate_crc_32(Span<const byte> data);

  static void pack_crc_32(uint8_t* buffer, uint32_t crc, uint32_t position);

  static uint32_t unpack_crc_32(Span<const byte> data);
  static uint32_t unpack_crc_32(uint8_t* buffer, uint32_t position);

  static uint8_t* derive_key(char* passphrase, uint8_t passphrase_len);
  static void generate_and_fill_IV(uint8_t* data_buffer);

  // Helpers
  static uint32_t calculate_num_blocks(uint32_t *data_len);

  static uint8_t calculate_padding_len(uint32_t *data_len, uint32_t num_blocks);
  static void xor_together(uint8_t* block1, uint8_t* block2);
  static uint8_t* copy_block(uint8_t* block);
  static void copy_block(uint8_t* block, uint8_t* destination);
  static void move_block(uint8_t* block, uint8_t* destination);

  static void phex(const uint8_t* str);

 public:
  Crypter();

  // TODO modify these to return structs
  // (after previous) TODO remove common code into pipeline methods eg. prepare_data
  // Assume data is passed in as a C-style string
  static std::vector<byte> ECB_encrypt(Span<const byte> data,
                              std::string passphrase); // Returns pointer to encrypted data, length updated
  static std::vector<byte> ECB_decrypt(Span<const byte> data,
                              std::string passphrase);

  static uint8_t *CBC_encrypt(uint8_t *data, uint32_t *data_len,
                              char *passphrase); // Returns pointer to encrypted data, length updated
  static uint8_t *CBC_decrypt(uint8_t *data, uint32_t *data_len, char *passphrase);

  static uint8_t *PCBC_encrypt(uint8_t *data, uint32_t *data_len,
                                char *passphrase);  // Returns pointer to encrypted data, length updated
  static uint8_t *PCBC_decrypt(uint8_t *data, uint32_t *data_len, char *passphrase);

  static std::vector<byte> CFB_encrypt(Span<const byte> data,
                              std::string passphrase);  // Returns pointer to encrypted data, length updated
  static uint8_t *CFB_decrypt(Span<const byte> data,
                              std::string passphrase);
};
#endif
