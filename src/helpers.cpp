#include "crypter.h"

// Helpers for the crypter class

// Given a data legnth and project settings return the number of blocks needed to store the encrypted data
uint32_t Crypter::calculate_num_blocks(uint32_t *data_len) {
  // this relies on integer division, adds additional block for padding if data length is exact multiple of block length
  return (((*data_len) + CRC_LEN) / BLOCK_SIZE) + 1;
}

uint8_t Crypter::calculate_padding_len(uint32_t *data_len, uint32_t num_blocks) {
    return (uint8_t) ((num_blocks * BLOCK_SIZE) - ((*data_len) + CRC_LEN));
}

// bock1 ^= block2
void Crypter::xor_together(uint8_t* block1, uint8_t* block2) {
  for (int i=0; i<BLOCK_SIZE; i++) {
    block1[i] ^= block2[i];
  }
}

uint8_t* Crypter::copy_block(uint8_t *block) {
  auto *new_block = new uint8_t[BLOCK_SIZE]();
  for (int i=0; i<BLOCK_SIZE; i++) {
    new_block[i] = block[i];
  }
  return new_block;
}

void Crypter::copy_block(uint8_t *block, uint8_t *destination) {
  for (int i=0; i<BLOCK_SIZE; i++) {
    destination[i] = block[i];
  }
}

// Movies data to new location, deletes original
// Destination must have capacity to store BLOCK_SIZE bytes
void Crypter::move_block(uint8_t *block, uint8_t *destination) {
  for (int i=0; i<BLOCK_SIZE; i++) {
    destination[i] = block[i];
  }
  memset(block, 0, BLOCK_SIZE);
}
