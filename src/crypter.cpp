// TODO order methods and imports alphabetically
#include <string.h>
#include <cstring>
#include <stdio.h>
#include <iostream>
#include <time.h>
#include <stdlib.h>

#include "crypter.h"
#include "../lib/aes.h"
#include "../test/test.h"

Crypter::Crypter() {
  srand((unsigned int)time(NULL));
}

// Encrypts data passed in and returns a buffer containing the encrypted data length
// Also modifies data_len to reflect the new legnth of the encrypted data
// CBC data buffer includes the IV in the first block
uint8_t* Crypter::CBC_encrypt(uint8_t* data, size_t* data_len, char* passphrase) {
  if (*data_len <= 0) {
    return NULL;
  }

  uint8_t* key = derive_key(passphrase);
  memset(key, 0, strlen(passphrase));

  size_t num_blocks = calculate_num_blocks(data_len) + 1; // additional block to store initialization vector
  size_t num_data_blocks = num_blocks -1;
  uint8_t padding_len = Crypter::calculate_padding_len(data_len, num_data_blocks);
  uint8_t* buffer = new uint8_t[num_blocks*BLOCK_SIZE];

  // Fills the first block with a random initialization vector (nounce)
  generate_and_fill_IV(buffer);

  // Copy input data into buffer after intialization vector
  for (size_t i=0; i < (*data_len); i++) {
    buffer[BLOCK_SIZE + i] = data[i];
  }

  // Append CRC after data
  uint32_t crc = calculate_crc_32(buffer + BLOCK_SIZE, (*data_len));
  pack_crc_32(buffer, crc, BLOCK_SIZE + (*data_len));

  // Padding according to PKCS #7 - always pad at least one byte
  for (size_t i = BLOCK_SIZE + (*data_len) + CRC_LEN; i < num_blocks * BLOCK_SIZE; i++) {
    buffer[i] = padding_len;
  }

  #ifdef DEBUG
  std::cout << "Raw data: \n";
  for (int i = 0; i < num_blocks; i++){
    Tests::phex(&buffer[i*BLOCK_SIZE]);
  }
  #endif

  // XOR IV with first block
  xor_together(&buffer[BLOCK_SIZE], &buffer[0]);
  AES128_ECB_encrypt(&buffer[BLOCK_SIZE], key);

  size_t current_block = 2;
  while (current_block <= num_data_blocks) {
    // XOR previous cyphertext with current plaintext, then encrypt
    xor_together(&buffer[BLOCK_SIZE*current_block], &buffer[BLOCK_SIZE * (current_block - 1)]);
    AES128_ECB_encrypt(&buffer[BLOCK_SIZE*current_block], key);
    ++current_block;
  }

  #ifdef DEBUG
  std::cout << "Encrypted data: \n";
  for (int i = 0; i < num_blocks; i++){
    Tests::phex(&buffer[i*BLOCK_SIZE]);
  }
  #endif

  // Clear the plaintext string and key
  memset(data, 0, (*data_len));
  memset(key, 0, BLOCK_SIZE);

  (*data_len) = num_blocks * BLOCK_SIZE;
  data = buffer;
  return data;
}


uint8_t* Crypter::CBC_decrypt(uint8_t *data, size_t *data_len, char *passphrase) {
  if (*data_len <= 0) {
    return NULL; // Can't decrypt no data
  }
  size_t original_data_len = *data_len;
  size_t num_data_blocks = (original_data_len / BLOCK_SIZE) - 1;
  uint8_t *key = derive_key(passphrase);

  #ifdef DEBUG
  std::cout << "\n\nInput data: \n";
  for (int i = 0; i < num_data_blocks + 1; i++){
    Tests::phex(&data[i*BLOCK_SIZE]);
  }
  #endif

  // For CBC we decrypt in reverse order due to dependence on previous block
  for (int i = num_data_blocks; i > 0; --i) {
    AES128_ECB_decrypt(&data[i * BLOCK_SIZE], key);
    xor_together(&data[i * BLOCK_SIZE], &data[(i - 1) * BLOCK_SIZE]);
  }

  size_t padding_len = data[(*data_len) - 1];
  // Update data_len to be length of the original message
  *data_len = (*data_len) - padding_len - CRC_LEN;

  #ifdef DEBUG
  std::cout << "Output data: \n";
  for (int i = 0; i < num_data_blocks + 1; i++){
    Tests::phex(&data[i*BLOCK_SIZE]);
  }
  #endif

  // Perform CRC verification
  uint32_t crc_value = unpack_crc_32(data, *data_len);
  if (crc_value != Crypter::calculate_crc_32(data + BLOCK_SIZE, (*data_len) - BLOCK_SIZE)) {
    std::cout << crc_value << " " << Crypter::calculate_crc_32(data, (*data_len));
    return NULL;
  }

  *data_len = *data_len - BLOCK_SIZE; // Don't include the IV in the length

  // Copy data minus IV and CRC/padding to new buffer to avoid memory leak or offset
  uint8_t *plaintext_buffer = new uint8_t[*data_len];
  for (int i = 0; i < (*data_len); i++) {
    plaintext_buffer[i] = data[BLOCK_SIZE + i];
  }


  // Clear original data buffer
  memset(data, 0, (num_data_blocks + 1) * BLOCK_SIZE);
  // Don't delete data buffer because it was allocated outside this library

  return plaintext_buffer;
}

uint8_t* Crypter::ECB_encrypt(uint8_t* data, size_t* data_len, char* passphrase) {
  // If no data passed in we can't do much
  if (*data_len <= 0) {
    return NULL;
  }

  uint8_t* key = derive_key(passphrase);

  size_t num_blocks = calculate_num_blocks(data_len);
  uint8_t padding_len = calculate_padding_len(data_len, num_blocks);
  uint8_t* buffer = new uint8_t[num_blocks*BLOCK_SIZE];

  // Copy data into buffer
  for (size_t i = 0; i < (*data_len); i++){
    buffer[i] = data[i];
  }
  // Add CRC in next CRC_LEN bytes
  uint32_t crc = calculate_crc_32(buffer, (*data_len));
  pack_crc_32(buffer, crc, *data_len);

  // Padding according to PKCS #7 - always pad at least one byte
  for (size_t i = (*data_len) + CRC_LEN; i < num_blocks * BLOCK_SIZE; i++) {
    buffer[i] = padding_len;
  }

  #ifdef DEBUG
  std::cout << "Input data: \n";
  for (int i = 0; i < num_blocks; i++){
    Tests::phex(&buffer[i*BLOCK_SIZE]);
  }
  #endif

  // Encrypt!
  for (size_t j = 0; j < num_blocks; j++) {
    AES128_ECB_encrypt(&buffer[j*BLOCK_SIZE], key);
  }

  #ifdef DEBUG
  std::cout << "Encrypted data: \n";
  for (int i = 0; i < num_blocks; i++){
    Tests::phex(&buffer[i*BLOCK_SIZE]);
  }
  #endif

  // Clear the plaintext string and key
  memset(data, 0, (*data_len));
  memset(key, 0, BLOCK_SIZE);

  (*data_len) = num_blocks * BLOCK_SIZE;
  data = buffer;
  return data;
}

uint8_t* Crypter::ECB_decrypt(uint8_t* data, size_t* data_len, char* passphrase) {
  if (*data_len <= 0){
    return NULL; // Can't decrypt no data
  }
  size_t original_data_len = *data_len;

  // Assuming the data is encrypted using this library, data length will always be an exact multiple of block length
  size_t num_blocks = (*data_len) / BLOCK_SIZE;
  uint8_t* key = Crypter::derive_key(passphrase);

  for (size_t i = 0; i < num_blocks; i++) {
    AES128_ECB_decrypt(&data[i*BLOCK_SIZE], key);
  }

  uint8_t padding_len = data[(*data_len) - 1];
  // Update data_len to be length of the original message
  *data_len = (*data_len) - padding_len - CRC_LEN;

  uint32_t crc_value = unpack_crc_32(data, *data_len);

  if (crc_value != Crypter::calculate_crc_32(data, *data_len)) {
    std::cout << crc_value << " " << Crypter::calculate_crc_32(data, (*data_len));
    return NULL;
  }
  // Clear out the crc and padding before returning to user
  memset(&data[*data_len], 0, (original_data_len - *data_len));

  return data;
}

uint8_t* Crypter::PCBC_encrypt(uint8_t *data, size_t *data_len, char *passphrase) {
  if (*data_len <= 0) {
    return NULL;
  }

  uint8_t* key = derive_key(passphrase);
  memset(key, 0, strlen(passphrase));

  size_t num_blocks = calculate_num_blocks(data_len) + 1; // additional block to store initialization vector
  size_t num_data_blocks = num_blocks - 1;
  uint8_t padding_len = Crypter::calculate_padding_len(data_len, num_data_blocks);
  uint8_t* buffer = new uint8_t[num_blocks*BLOCK_SIZE];

  // Fills the first block with a random initialization vector (nounce)
  generate_and_fill_IV(buffer);

  // Copy input data into buffer after intialization vector
  for (size_t i=0; i < (*data_len); i++) {
    buffer[BLOCK_SIZE + i] = data[i];
  }

  // Append CRC after data
  uint32_t crc = calculate_crc_32(buffer + BLOCK_SIZE, (*data_len));
  pack_crc_32(buffer, crc, BLOCK_SIZE + (*data_len));

  // Padding according to PKCS #7 - always pad at least one byte
  for (size_t i = BLOCK_SIZE + (*data_len) + CRC_LEN; i < num_blocks * BLOCK_SIZE; i++) {
    buffer[i] = padding_len;
  }

  #ifdef DEBUG
  std::cout << "Raw data: \n";
  for (int i = 0; i < num_blocks; i++){
    Tests::phex(&buffer[i*BLOCK_SIZE]);
  }
  #endif

  uint8_t* cypher_input_block = &buffer[0]; // initialization vector
  uint8_t* block_plaintext = NULL;

  for (int i=1; i<=num_data_blocks; i++){
     block_plaintext = copy_block(&buffer[BLOCK_SIZE*i]);

    xor_together(&buffer[i*BLOCK_SIZE], cypher_input_block);
    AES128_ECB_encrypt(&buffer[i*BLOCK_SIZE], key);

    if (i < num_data_blocks) {
      cypher_input_block = block_plaintext;
      xor_together(cypher_input_block, &buffer[i*BLOCK_SIZE]); // plaintext XOR cyphertext
    }
  }

  #ifdef DEBUG
  std::cout << "Encrypted data: \n";
  for (int i = 0; i < num_blocks; i++){
    Tests::phex(&buffer[i*BLOCK_SIZE]);
  }
  #endif

  // Clear the plaintext string and key
  memset(data, 0, (*data_len));
  memset(key, 0, BLOCK_SIZE);

  (*data_len) = num_blocks * BLOCK_SIZE;
  data = buffer;
  return data;

}

uint8_t* Crypter::PCBC_decrypt(uint8_t *data, size_t *data_len, char *passphrase) {
  if (*data_len <= 0) {
    return NULL; // Can't decrypt no data
  }

  size_t original_data_len = *data_len;
  size_t num_data_blocks = (original_data_len / BLOCK_SIZE) - 1;
  uint8_t *key = derive_key(passphrase);

  #ifdef DEBUG
  std::cout << "\n\nInput data: \n";
  for (int i = 0; i < num_data_blocks + 1; i++){
    Tests::phex(&data[i*BLOCK_SIZE]);
  }
  #endif

  uint8_t* cypher_input_block = &data[0]; // IV
  uint8_t* previous_cyphertext = NULL;

  for (int i=1; i<=num_data_blocks; i++){
    previous_cyphertext = copy_block(&data[i*BLOCK_SIZE]);

    // Decrypt block, then XOR with the cypher input block
    AES128_ECB_decrypt(&data[i*BLOCK_SIZE], key);
    xor_together(&data[i*BLOCK_SIZE], cypher_input_block);

    if (i < num_data_blocks){
      // TODO fix memory leaks when we copy blocks
      // Prepare for decrypting next block
      cypher_input_block = previous_cyphertext;
      xor_together(cypher_input_block, &data[i*BLOCK_SIZE]); // previous cypher text XOR plaintext
    }
  }

  #ifdef DEBUG
  std::cout << "Output data: \n";
  for (int i = 0; i < num_data_blocks + 1; i++){
    Tests::phex(&data[i*BLOCK_SIZE]);
  }
  #endif

  size_t padding_len = data[(*data_len) - 1];
  if (padding_len > BLOCK_SIZE) return 0; // Decryption has gone wrong

  // Update data_len to be length of the original message
  *data_len = (*data_len) - padding_len - CRC_LEN;



  // Perform CRC verification
  uint32_t crc_value = unpack_crc_32(data, *data_len);
  if (crc_value != Crypter::calculate_crc_32(data + BLOCK_SIZE, (*data_len) - BLOCK_SIZE)) {
    std::cout << crc_value << " " << Crypter::calculate_crc_32(data, (*data_len));
    return NULL;
  }

  *data_len = *data_len - BLOCK_SIZE; // Don't include the IV in the length

  // Copy data minus IV and CRC/padding to new buffer to avoid memory leak or offset
  uint8_t *plaintext_buffer = new uint8_t[*data_len];
  for (int i = 0; i < (*data_len); i++) {
    plaintext_buffer[i] = data[BLOCK_SIZE + i];
  }

  // Clear original data buffer
  memset(data, 0, (num_data_blocks + 1) * BLOCK_SIZE);
  // Don't delete data buffer because it was allocated outside this library

  return plaintext_buffer;
}
