#include "crypter.h"

// Helpers for the crypter class

// Given a data legnth and project settings return the number of blocks needed to store the encrypted data
size_t Crypter::calculate_num_blocks(size_t* data_len) {
  // this relies on integer division, adds additional block for padding if data length is exact multiple of block length
  return (((*data_len) + CRC_LEN) / BLOCK_SIZE) + 1;
}

uint8_t Crypter::calculate_padding_len(size_t* data_len, size_t num_blocks) {
  return (num_blocks * BLOCK_SIZE) - ((*data_len) + CRC_LEN);
}

// bock1 ^= block2
void Crypter::xor_together(uint8_t* block1, uint8_t* block2) {
  for (int i=0; i<BLOCK_SIZE; i++) {
    block1[i] ^= block2[i];
  }
}

uint8_t* Crypter::copy_block(uint8_t *block) {
  uint8_t* new_block = new uint8_t[BLOCK_SIZE];
  for (int i=0; i<BLOCK_SIZE; i++) {
    new_block[i] = block[i];
  }
  return new_block;
}
