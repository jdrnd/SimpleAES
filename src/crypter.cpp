#include <string.h>
#include <cstring>
#include <stdio.h>
#include <iostream>

#include "crypter.h"
#include "lib/aes.h"
#include "test/test.h"

// 32 bit CRC polynomial from the ethenet standard
#define CRC_POLY 0xEDB88320
#define CRC_LEN 4

// Cyclic redundancy check (CRC) caculation
uint32_t Crypter::calculate_crc_32(uint8_t *data, size_t length) {
    uint32_t crc = 0;
    uint8_t i;

    crc = ~crc;
    while (length--) {
        crc ^= *data++;
        for (i = 0; i < 8; i++)
            crc = crc & 1 ? (crc >> 1) ^ CRC_POLY : crc >> 1;
    }
    return ~crc;
}

// TODO write tests for these
// Packs the 32bit crc value into 4 8-bit integers in buffer at a given position
void Crypter::pack_crc_32(uint8_t* buffer, uint32_t crc, uint16_t position) {
  for (int i = 0; i<CRC_LEN; i++){
    buffer[position + i] = crc >> (32 - 8*(i + 1));
  }
}

uint32_t Crypter::unpack_crc_32(uint8_t* buffer, uint16_t position) {
  uint32_t crc = 0;
  for (int i=0; i < CRC_LEN; i++) {
    crc |= buffer[position+i] << (32 - 8*(i+1));
  }
  return crc;
}

uint8_t* Crypter::ECB_encrypt(uint8_t* data, uint16_t* data_len, char* passphrase) {
  // If no data passed in we can't do much
  if (*data_len <= 0) {
    return NULL;
  }

  size_t num_blocks = ( ((*data_len) + CRC_LEN) / BLOCK_SIZE) + 1; // this relies on integer division, adds additional block for padding if data length is exact multiple of block length
  uint8_t padding_len = (num_blocks * BLOCK_SIZE) - ((*data_len) + CRC_LEN);
  uint8_t* buffer = new uint8_t[num_blocks*BLOCK_SIZE];

  // Copy data into buffer
  for (size_t i = 0; i < (*data_len); i++){
    buffer[i] = data[i];
  }
  // Add CRC in next CRC_LEN bytes
  uint32_t crc = Crypter::calculate_crc_32(buffer, (*data_len));
  pack_crc_32(buffer, crc, *data_len);

  // Padding according to PKCS #7 - always pad at least one byte
  for (size_t i = (*data_len) + CRC_LEN; i < num_blocks * BLOCK_SIZE; i++) {
    buffer[i] = padding_len;
  }

  // DEBUG FIXME
  std::cout << "Input data: ";
  for (int i = 0; i < num_blocks; i++){
    Tests::phex(&buffer[i*BLOCK_SIZE]);
  }

  uint8_t* key = Crypter::derive_key(passphrase);
  // Encrypt!
  for (size_t j = 0; j < num_blocks; j++) {
    AES128_ECB_encrypt(&buffer[j*BLOCK_SIZE], key);
  }

  // DEBUG FIXME
  std::cout << "Encrypted data: ";
  for (int i = 0; i < num_blocks; i++){
    Tests::phex(&buffer[i*BLOCK_SIZE]);
  }

  // Clear the plaintext string and key
  memset(data, 0, (*data_len));
  memset(key, 0, BLOCK_SIZE);

  (*data_len) = num_blocks * BLOCK_SIZE;
  data = buffer;
  return data;
}


uint8_t* Crypter::ECB_decrypt(uint8_t* data, uint16_t* data_len, char* passphrase) {
  if (*data_len <= 0){
    return NULL; // Can't decrypt no data
  }
  uint16_t original_data_len = *data_len;

  std::cout << "Encrypted data: ";
  Tests::phex(data);

  // Assuming the data is encrypted using this library, data lenxgth will always be an exact multiple of block length
  size_t num_blocks = (*data_len) / BLOCK_SIZE;
  uint8_t* key = Crypter::derive_key(passphrase);

  for (size_t i = 0; i < num_blocks; i++) {
    AES128_ECB_decrypt(&data[i*BLOCK_SIZE], key);
  }

  uint8_t padding_len = data[(*data_len) - 1];
  // Update data_len to be legnth of the original message
  *data_len = (*data_len) - padding_len - CRC_LEN;

  uint32_t crc_value = unpack_crc_32(data, *data_len);

  if (crc_value != Crypter::calculate_crc_32(data, *data_len)) {
    std::cout << crc_value << " " << Crypter::calculate_crc_32(data, (*data_len));
    return NULL;
  }
  // Clear out the crc and padding before returning to user
  memset(&data[*data_len], 0, (original_data_len - *data_len));

  std::cout << "Decrypted data: ";
  Tests::phex(data);
  return data;
}

// TODO replace this with a REAL key derivation function
uint8_t* Crypter::derive_key(char* passphrase) {
  uint8_t* key_buffer = new uint8_t[BLOCK_SIZE];

  size_t passphrase_len;
  if (passphrase != NULL){
    passphrase_len = strlen(passphrase);
  }
  else {
    passphrase_len = 0;
  }

  for (uint8_t i = 0; i < passphrase_len; i++) {
    key_buffer[i] = passphrase[i];
  }

  // Use PKCS-style padding here because why not
  uint8_t padding_len = BLOCK_SIZE - passphrase_len;
  for (uint8_t i = passphrase_len; i < BLOCK_SIZE; i++) {
    key_buffer[i] = padding_len;
  }
  memset(passphrase, 0, passphrase_len);

  return key_buffer;
}
