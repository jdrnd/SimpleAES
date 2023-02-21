#include <cstdlib>

#include "crypter.h"
#include "lib/aes.h"
#include <iostream>


// Cryptographic utilities for the crypter class

// Cyclic redundancy check (CRC) caculation
uint32_t Crypter::calculate_crc_32(uint8_t *data, uint32_t length) {
    uint32_t crc = 0;
    uint8_t i;

    crc = ~crc;
    while (length--) {
        crc ^= *data++;
        for (i = 0; i < 8; i++) {
          crc = crc & 1 ? (crc >> 1) ^ CRC_POLY : crc >> 1;
        }
    }
    return ~crc;
}

uint32_t Crypter::calculate_crc_32(Span<const byte> data) {
  uint32_t crc = 0;

  crc = ~crc;
  for (size_t i = 0; i < data.length(); i++) {
      crc ^= data[i];
      for (uint8_t j = 0; j < 8; j++) {
        crc = crc & 1 ? (crc >> 1) ^ CRC_POLY : crc >> 1;
      }
  }
  return ~crc;
}

// TODO write tests for these
// Packs the 32bit crc value into 4 8-bit integers in buffer at a given position
void Crypter::pack_crc_32(uint8_t* buffer, uint32_t crc, uint32_t position) {
  for (int i = 0; i<CRC_LEN; i++){
    buffer[position + i] = (uint8_t) (crc >> (uint32_t) (32 - 8 * (i + 1))) & 0x000000FF;
  }
}

uint32_t Crypter::unpack_crc_32(uint8_t* buffer, uint32_t position) {
  uint32_t crc = 0;
  for (int i=0; i < CRC_LEN; i++) {
    crc |= buffer[position+i] << (32 - 8*(i+1));
  }
  return crc;
}

uint32_t Crypter::unpack_crc_32(Span<const byte> data) {
  uint32_t crc = 0;
  for (int i=0; i < CRC_LEN; i++) {
    crc |= data[i] << (32 - 8*(i+1));
  }
  return crc;
}

// Generates and fills buffer with BLOCK_SIZE random bytes
void Crypter::generate_and_fill_IV(uint8_t* data_buffer) {
  // TODO use a secure PRNG
  for (int i=0; i<BLOCK_SIZE; i++) {
    data_buffer[i] = rand() % UINT8_MAX;
  }
}

// TODO replace this with a REAL key derivation function
uint8_t* Crypter::derive_key(char* passphrase, uint8_t passphrase_len) {
  uint8_t* key_buffer = new uint8_t[BLOCK_SIZE]();

  for (uint8_t i = 0; i < passphrase_len; i++) {
    if (i >= BLOCK_SIZE) { break; }
    key_buffer[i] = (uint8_t) passphrase[i];
  }

  // Use PKCS-style padding here because why not
  int8_t padding_len = BLOCK_SIZE - passphrase_len; // Loop does nothing if padding length is negative
    for (uint32_t i = passphrase_len; i < BLOCK_SIZE; i++) {
    key_buffer[i] = padding_len;
  }
  memset(passphrase, 0, passphrase_len);

  return key_buffer;
}

void Crypter::phex(const uint8_t* str)
{
    uint8_t i;
    for(i = 0; i < BLOCK_SIZE; ++i){
        printf("%.2x", str[i]);
    }
    printf("\n");
}
