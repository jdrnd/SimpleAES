AES Code taken From [https://github.com/kokke/tiny-AES128-C], with modifications for C++ usage and tests

Modifications: removed the CBC implementation as I do that myself, and modified ECB to encrypt/decrypt in place.
### Tiny AES128 in C

This is a small and portable implementation of the AES128 ECB and CBC encryption algorithms written in C.

The API that we're using here is very simple and looks like this (Uses C99 `<cstdint>`-style annotated types):

```C
// Modified to encrypt/decrypt in-place so output buffer === input buffer
void AES128_ECB_encrypt(uint8_t* input, const uint8_t* key);
void AES128_ECB_decrypt(uint8_t* input, const uint8_t* key);
```

There is no built-in error checking or protection from out-of-bounds memory access errors as a result of malicious input. The two functions AES128_ECB_xxcrypt() do the work, and they expect inputs of 128 bit length.
