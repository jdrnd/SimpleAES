#ifndef _AES_H_
#define _AES_H_

#include <cstdint>

#ifndef ECB
  #define ECB 1
#endif

#define BLOCK_SIZE 16 // 128 bit encryption


#if defined(ECB) && ECB

// These function encrypt/decrypt in-place
// Data and key MUST both be 16 bytes long
void AES128_ECB_encrypt(uint8_t* data, const uint8_t* key);
void AES128_ECB_decrypt(uint8_t* data, const uint8_t* key);

void AES128_ECB_encrypt(const uint8_t* data, uint8_t* output, const uint8_t* key);
void AES128_ECB_decrypt(const uint8_t* data, uint8_t output, const uint8_t* key);

#endif // #if defined(ECB) && ECB



#endif //_AES_H_
