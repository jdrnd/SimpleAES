// TODO order methods and imports alphabetically
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>

#include "crypter.h"
#include "lib/aes.h"
#include "types.h"

#define DEBUG

namespace {
  void Xor_together(uint8_t* block1, Span<const byte> block2) {
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
      block1[i] ^= block2[i];
    }
  }
}

Crypter::Crypter() {
    srand((unsigned int) time(0));
}

// Encrypts data passed in and returns a buffer containing the encrypted data length
// Also modifies data_len to reflect the new legnth of the encrypted data
// CBC data buffer includes the IV in the first block
uint8_t *Crypter::CBC_encrypt(uint8_t *data, uint32_t *data_len, char *passphrase) {
  if (*data_len <= 0) {
      return nullptr;
  }

  uint8_t* key = derive_key(passphrase, BLOCK_SIZE);
  memset(key, 0, strlen(passphrase));

  uint32_t num_blocks = calculate_num_blocks(data_len) + 1; // additional block to store initialization vector
  uint32_t num_data_blocks = num_blocks - 1;
  uint8_t padding_len = Crypter::calculate_padding_len(data_len, num_data_blocks);
  auto *buffer = new uint8_t[num_blocks * BLOCK_SIZE]();

  // Fills the first block with a random initialization vector (nounce)
  generate_and_fill_IV(buffer);

  // Copy input data into buffer after intialization vector
    for (uint32_t i = 0; i < (*data_len); i++) {
    buffer[BLOCK_SIZE + i] = data[i];
  }

  // Append CRC after data
  uint32_t crc = calculate_crc_32(buffer + BLOCK_SIZE, (*data_len));
    pack_crc_32(buffer, crc, BLOCK_SIZE + (uint32_t) (*data_len));

  // Padding according to PKCS #7 - always pad at least one byte
    for (uint32_t i = BLOCK_SIZE + (*data_len) + CRC_LEN; i < num_blocks * BLOCK_SIZE; i++) {
    buffer[i] = padding_len;
  }

  #ifdef DEBUG
  std::cout << "Raw data: \n";
  for (uint32_t i = 0; i < num_blocks; i++){
    phex(&buffer[i*BLOCK_SIZE]);
  }
  #endif

  // XOR IV with first block
  xor_together(&buffer[BLOCK_SIZE], &buffer[0]);
  AES128_ECB_encrypt(&buffer[BLOCK_SIZE], key);

    uint32_t current_block = 2;
  while (current_block <= num_data_blocks) {
    // XOR previous cyphertext with current plaintext, then encrypt
    xor_together(&buffer[BLOCK_SIZE*current_block], &buffer[BLOCK_SIZE * (current_block - 1)]);
    AES128_ECB_encrypt(&buffer[BLOCK_SIZE*current_block], key);
    ++current_block;
  }

  #ifdef DEBUG
  std::cout << "Encrypted data: \n";
  for (uint32_t i = 0; i < num_blocks; i++){
    phex(&buffer[i*BLOCK_SIZE]);
  }
  #endif

  // Clear the plaintext string and key
  memset(data, 0, (*data_len));
  memset(key, 0, BLOCK_SIZE);

  (*data_len) = num_blocks * BLOCK_SIZE;
  data = buffer;
  return data;
}


uint8_t *Crypter::CBC_decrypt(uint8_t *data, uint32_t *data_len, char *passphrase) {
  if (*data_len <= 0) {
      return nullptr; // Can't decrypt no data
  }

  uint32_t original_data_len = *data_len;
  uint32_t num_data_blocks = (original_data_len / BLOCK_SIZE) - 1;
  uint8_t *key = derive_key(passphrase, BLOCK_SIZE);

  #ifdef DEBUG
  std::cout << "\n\nInput data: \n";
  for (uint32_t i = 0; i < num_data_blocks + 1; i++){
    phex(&data[i*BLOCK_SIZE]);
  }
  #endif

  // For CBC we decrypt in reverse order due to dependence on previous block
  for (int i = num_data_blocks; i > 0; --i) {
    AES128_ECB_decrypt(&data[i * BLOCK_SIZE], key);
    xor_together(&data[i * BLOCK_SIZE], &data[(i - 1) * BLOCK_SIZE]);
  }

    uint32_t padding_len = data[(*data_len) - 1];
  // Update data_len to be length of the original message
  *data_len = (*data_len) - padding_len - CRC_LEN;

  #ifdef DEBUG
  std::cout << "Output data: \n";
  for (uint32_t i = 0; i < num_data_blocks + 1; i++){
    phex(&data[i*BLOCK_SIZE]);
  }
  #endif

  // Perform CRC verification
  uint32_t crc_value = unpack_crc_32(data, *data_len);
  if (crc_value != Crypter::calculate_crc_32(data + BLOCK_SIZE, (*data_len) - BLOCK_SIZE)) {
    std::cout << crc_value << " " << Crypter::calculate_crc_32(data, (*data_len));
      return nullptr;
  }

  *data_len = *data_len - BLOCK_SIZE; // Don't include the IV in the length

  // Copy data minus IV and CRC/padding to new buffer to avoid memory leak or offset
    auto *plaintext_buffer = new uint8_t[*data_len]();
  for (uint i = 0; i < (*data_len); i++) {
    plaintext_buffer[i] = data[BLOCK_SIZE + i];
  }


  // Clear original data buffer
  memset(data, 0, (num_data_blocks + 1) * BLOCK_SIZE);
  // Don't delete data buffer because it was allocated outside this library

  return plaintext_buffer;
}

std::vector<byte> Crypter::ECB_encrypt(Span<const byte> data,
                                           std::string passphrase) {
  if (data.size() <= 0) {
      return {};
  }
  Key key{Key::CreateSecure(passphrase)};

  // this relies on integer division, adds additional block for padding if data length is exact multiple of block length
  uint32_t num_blocks = (data.size() + CRC_LEN) / BLOCK_SIZE + 1;
  uint32_t output_data_size = num_blocks*BLOCK_SIZE;

  uint8_t padding_len = (uint8_t) ((num_blocks * BLOCK_SIZE) - (data.size() + CRC_LEN));
  
  std::vector<byte> buffer;
  buffer.resize(output_data_size);

  // Copy data into buffer
  for (uint32_t i = 0; i < data.size(); i++) {
    buffer[i] = data[i];
  }
  // Add CRC in next CRC_LEN bytes
  uint32_t crc = calculate_crc_32(buffer.data(), data.size());
  pack_crc_32(buffer.data(), crc, data.size());

  // Padding according to PKCS #7 - always pad at least one byte
  for (uint32_t i = data.size() + CRC_LEN; i < output_data_size; i++) {
    buffer[i] = padding_len;
  }

  #ifdef DEBUG
  std::cout << "Input data: \n";
  for (uint32_t i = 0; i < num_blocks; i++){
    phex(&buffer[i*BLOCK_SIZE]);
  }
  #endif

  // Encrypt!
  for (uint32_t j = 0; j < num_blocks; j++) {
    AES128_ECB_encrypt(&buffer[j*BLOCK_SIZE], key.data());
  }

  #ifdef DEBUG
  std::cout << "Encrypted data: \n";
  for (uint32_t i = 0; i < num_blocks; i++){
    phex(&buffer[i*BLOCK_SIZE]);
  }
  #endif

  return buffer;
}

std::vector<byte> Crypter::ECB_decrypt(Span<const byte> data,
                              std::string passphrase) {
  if (data.size() <= 0){
      return {}; // Can't decrypt no data
  }

  std::vector<byte> output;
  output.resize(data.size());
  for (uint i = 0; i < data.size(); i++)
  {
    output[i] = data[i];
  }

  // Assuming the data is encrypted using this library, data length will always be an exact multiple of block length
  uint32_t num_blocks = data.size() / BLOCK_SIZE;
  Key key{Key::CreateSecure(passphrase)};

    for (uint32_t i = 0; i < num_blocks; i++) {
    AES128_ECB_decrypt(&output[i*BLOCK_SIZE], key.data());
  }

  uint8_t padding_len = output.back();
  uint32_t message_len = output.size() - CRC_LEN - padding_len;

  Span<const byte> crc_data = absl::MakeSpan(output).subspan(message_len, message_len+4);
  uint32_t crc_value = unpack_crc_32(crc_data);
  Span<const byte> raw_data = absl::MakeSpan(output).subspan(message_len);

  if (crc_value != Crypter::calculate_crc_32(raw_data)) {
    std::cout << crc_value << " " << Crypter::calculate_crc_32(raw_data);
    return {};
  }

  return output;
}

uint8_t *Crypter::PCBC_encrypt(uint8_t *data, uint32_t *data_len, char *passphrase) {
  if (*data_len <= 0) {
      return nullptr;
  }

  uint8_t* key = derive_key(passphrase, BLOCK_SIZE);
  memset(key, 0, strlen(passphrase));

  uint32_t num_blocks = calculate_num_blocks(data_len) + 1; // additional block to store initialization vector
  uint32_t num_data_blocks = num_blocks - 1;
  uint8_t padding_len = Crypter::calculate_padding_len(data_len, num_data_blocks);
  uint8_t* buffer = new uint8_t[num_blocks*BLOCK_SIZE]();

  // Fills the first block with a random initialization vector (nounce)
  generate_and_fill_IV(buffer);

  // Copy input data into buffer after intialization vector
    for (uint32_t i = 0; i < (*data_len); i++) {
    buffer[BLOCK_SIZE + i] = data[i];
  }

  // Append CRC after data
  uint32_t crc = calculate_crc_32(buffer + BLOCK_SIZE, (*data_len));
  pack_crc_32(buffer, crc, BLOCK_SIZE + (*data_len));

  // Padding according to PKCS #7 - always pad at least one byte
    for (uint32_t i = BLOCK_SIZE + (*data_len) + CRC_LEN; i < num_blocks * BLOCK_SIZE; i++) {
    buffer[i] = padding_len;
  }

  #ifdef DEBUG
  std::cout << "Raw data: \n";
  for (uint32_t i = 0; i < num_blocks; i++){
    phex(&buffer[i*BLOCK_SIZE]);
  }
  #endif

  uint8_t* cypher_input_block = &buffer[0]; // initialization vector
    uint8_t *block_plaintext = nullptr;

  for (uint i=1; i<=num_data_blocks; i++){
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
  for (uint32_t i = 0; i < num_blocks; i++){
    phex(&buffer[i*BLOCK_SIZE]);
  }
  #endif

  // Clear the plaintext string and key
  memset(data, 0, (*data_len));
  memset(key, 0, BLOCK_SIZE);

  (*data_len) = num_blocks * BLOCK_SIZE;
  data = buffer;
  return data;

}

uint8_t *Crypter::PCBC_decrypt(uint8_t *data, uint32_t *data_len, char *passphrase) {
  if (*data_len <= 0) {
      return nullptr; // Can't decrypt no data
  }

  uint32_t original_data_len = *data_len;
  uint32_t num_data_blocks = (original_data_len / BLOCK_SIZE) - 1;
  uint8_t *key = derive_key(passphrase, BLOCK_SIZE);

  #ifdef DEBUG
  std::cout << "\n\nInput data: \n";
  for (uint32_t i = 0; i < num_data_blocks + 1; i++){
    phex(&data[i*BLOCK_SIZE]);
  }
  #endif

  uint8_t* cypher_input_block = &data[0]; // IV
    uint8_t *previous_cyphertext = nullptr;

  for (uint i=1; i<=num_data_blocks; i++){
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
  for (uint32_t i = 0; i < num_data_blocks + 1; i++){
    phex(&data[i*BLOCK_SIZE]);
  }
  #endif

    uint32_t padding_len = data[(*data_len) - 1];
    if (padding_len > BLOCK_SIZE) return nullptr; // Decryption has gone wrong

  // Update data_len to be length of the original message
  *data_len = (*data_len) - padding_len - CRC_LEN;



  // Perform CRC verification
  uint32_t crc_value = unpack_crc_32(data, *data_len);
  if (crc_value != Crypter::calculate_crc_32(data + BLOCK_SIZE, (*data_len) - BLOCK_SIZE)) {
    std::cout << crc_value << " " << Crypter::calculate_crc_32(data, (*data_len));
      return nullptr;
  }

  *data_len = *data_len - BLOCK_SIZE; // Don't include the IV in the length

  // Copy data minus IV and CRC/padding to new buffer to avoid memory leak or offset
  uint8_t *plaintext_buffer = new uint8_t[*data_len]();
  for (uint i = 0; i < (*data_len); i++) {
    plaintext_buffer[i] = data[BLOCK_SIZE + i];
  }

  // Clear original data buffer
  memset(data, 0, (num_data_blocks + 1) * BLOCK_SIZE);
  // Don't delete data buffer because it was allocated outside this library

  return plaintext_buffer;
}

std::vector<uint8_t> Crypter::CFB_encrypt(Span<const byte> data,
                                           std::string passphrase) {
  printf("%lu\n", data.size());
  if (data.size() <= 0) {
      return {};
  }
  Key key{Key::CreateSecure(passphrase)};

  // this relies on integer division, adds additional block for padding if data length is exact multiple of block length
  // plus a block for the initialization vector
  uint32_t num_blocks = (data.size() + CRC_LEN) / BLOCK_SIZE + 2;
  uint32_t num_data_blocks = num_blocks - 1;
  uint32_t output_data_size = num_blocks*BLOCK_SIZE;

  uint8_t padding_len = (uint8_t) ((num_blocks * BLOCK_SIZE) - (data.size() + CRC_LEN));
  
  std::vector<byte> buffer;
  buffer.resize(output_data_size);

  // Create array of block views to simplify code
  std::vector<Span<byte>> blocks;
  for (size_t i = 0; i < num_blocks; i++) {
    blocks.push_back(absl::MakeSpan(&buffer[i * BLOCK_SIZE], BLOCK_SIZE));
  }

  // Fills the first block with a random initialization vector (nounce)
  generate_and_fill_IV(&buffer[0]);
  // Copy the IV into the "first" block's position
  copy_block(&buffer[0], &buffer[BLOCK_SIZE]);

  // Copy input data into buffer after initialization vector
  for (uint32_t i = 0; i < data.size(); i++) {
    buffer[BLOCK_SIZE + i] = data[i];
  }

  // Append CRC after data
  uint32_t crc = calculate_crc_32(&buffer[BLOCK_SIZE], data.size());
  pack_crc_32(&buffer[0], crc, BLOCK_SIZE + data.size());

  // Padding according to PKCS #7 - always pad at least one byte
    for (uint32_t i = BLOCK_SIZE + data.size() + CRC_LEN; i < num_blocks * BLOCK_SIZE; i++) {
    buffer[i] = padding_len;
  }

  #ifdef DEBUG
      std::cout << "Raw data: \n";
    for (uint32_t i = 0; i < num_blocks; i++) {
      phex(&buffer[i*BLOCK_SIZE]);
    }
  #endif

  // Encrypt previous encrypted block (starting with IV), then XOR with current block plaintext
  uint32_t current_block_num = 1;
  uint8_t prev_cyphertext[BLOCK_SIZE];

  while (current_block_num <= num_data_blocks) {
    // encrypt previous block, then XOR with next block's plaintext
    copy_block(&buffer[(current_block_num - 1) * BLOCK_SIZE], prev_cyphertext);
    AES128_ECB_encrypt(prev_cyphertext, key.data());

    xor_together(&buffer[current_block_num * BLOCK_SIZE], prev_cyphertext);

    current_block_num++;
  }

  // Erase trailing plaintext block
  //memset(&buffer[current_block_num * BLOCK_SIZE], 0, BLOCK_SIZE);

  #ifdef DEBUG
    std::cout << "Encrypted data: \n";
    for (uint32_t i = 0; i < num_blocks; i++){
      phex(&buffer[i*BLOCK_SIZE]);
    }
  #endif

  //data.size() = num_blocks * BLOCK_SIZE;
  return buffer;
}

uint8_t *Crypter::CFB_decrypt(Span<byte> data,
                              std::string passphrase) {
  if (data.size() <= 0) {
      return nullptr;  // Can't decrypt no data
  }

  Key key{Key::CreateSecure(passphrase)};
  uint32_t const dataSize = data.size();

  // Ignore the IV block at the start
  uint32_t num_data_blocks = (dataSize / BLOCK_SIZE) - 1;

  uint8_t* temp_buffer = new uint8_t[dataSize];
  uint8_t* temp = &temp_buffer[0];

  #ifdef DEBUG
    std::cout << "\n\nInput data: \n";
    for (uint32_t i = 0; i < num_data_blocks + 1; i++){
      phex(&data[i*BLOCK_SIZE]);
    }
  #endif

  uint32_t current_block_num = 1;

  // We don't need the initialization vector after this point so we can overwrite it
  while (current_block_num <= num_data_blocks) {
    AES128_ECB_encrypt(&data[current_block_num * BLOCK_SIZE - BLOCK_SIZE],
                       &temp[current_block_num * BLOCK_SIZE - BLOCK_SIZE],
                       key.data()); // Yes, the CFB decryption stage uses AES encryption, see the CFB spec for more details
    Xor_together(&temp[current_block_num * BLOCK_SIZE - BLOCK_SIZE],  data.subspan(current_block_num * BLOCK_SIZE, current_block_num * BLOCK_SIZE + BLOCK_SIZE));

    current_block_num++;
  }

  // Clear old cyphertext
  memcpy(data.data() + BLOCK_SIZE, temp, dataSize);

  // PKCS padding means the last value in the buffer is the number of padded bytes
  uint32_t padding_len = data[dataSize - 1];

  // Update data_len to be length of the original message
  // Again extra block of cyphertext is left at end
  uint32_t originalDataSize = dataSize - padding_len - CRC_LEN - BLOCK_SIZE;


  #ifdef DEBUG
    std::cout << "Output data: \n";
    // We overwrite the IV block here
    for (uint32_t i = 0; i < num_data_blocks + 1; i++){
      phex(&data[i*BLOCK_SIZE]);
    }
  #endif

  // Perform CRC verification
  size_t crc_start_idx = BLOCK_SIZE + originalDataSize;
  Span<const byte> crc_data = data.subspan(crc_start_idx, crc_start_idx+4);

  Span<const byte> raw_data = data.subspan(BLOCK_SIZE, BLOCK_SIZE + originalDataSize);

  uint32_t crc_value = unpack_crc_32(crc_data);
  if (crc_value != Crypter::calculate_crc_32(raw_data)) {
    std::cout << std::endl << crc_value << " " << Crypter::calculate_crc_32(raw_data) << std::endl;
    return nullptr;
  }

  // Copy data minus IV and CRC/padding to new buffer to avoid memory leak or offset
  uint8_t *plaintext_buffer = new uint8_t[originalDataSize]();
  for (uint i = 0; i < originalDataSize; i++) {
    plaintext_buffer[i] = data[BLOCK_SIZE + i];
  }

  return plaintext_buffer;
}