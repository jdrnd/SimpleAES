AES Code taken From [https://github.com/kokke/tiny-AES128-C], with modifications for C++ usage and tests
### Tiny AES128 in C

This is a small and portable implementation of the AES128 ECB and CBC encryption algorithms written in C.

The API is very simple and looks like this (I am using C99 `<stdint.h>`-style annotated types):

```C
void AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t* output);
void AES128_ECB_decrypt(uint8_t* input, const uint8_t* key, uint8_t* output);
void AES128_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);
void AES128_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);
```

You can choose to use one or both of the modes-of-operation, by defining the symbols CBC and ECB. See the header file for clarification.

There is no built-in error checking or protection from out-of-bounds memory access errors as a result of malicious input. The two functions AES128_ECB_xxcrypt() do most of the work, and they expect inputs of 128 bit length.
