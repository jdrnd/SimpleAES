#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>


// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES128 encryption in CBC-mode of operation and handles 0-padding.
// ECB enables the basic ECB 16-byte block algorithm. Both can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.


#ifndef ECB
  #define ECB 1
#endif

#define BLOCK_SIZE 16 // 128 bit encryption


#if defined(ECB) && ECB

// These function encrypt/decrypt in-place
// Data and key MUST both be 16 bytes long
void AES128_ECB_encrypt(uint8_t* data, const uint8_t* key);
void AES128_ECB_decrypt(uint8_t* data, const uint8_t* key);

#endif // #if defined(ECB) && ECB



#endif //_AES_H_
