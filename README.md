# SimpleAES Library

This library is designed to provide an easy interface to 128-bit AES encryption.

Building off an extremely minimal AES ECB implementation this library strives to do the following (none of which is provided by the ECB code):
  - [ ] Protect against memory out of bounds errors
  - [ ] Allow for inputs of arbitrary length, not just 16 bytes
  - [ ] Provide message authentication and integrity verification
  - [ ] Detect when an incorrect key is being used (rather than spitting out gibberish)
  - [ ] Implement CBC, PCBC, CFB, OFB, and CTR modes of operation


### Project Status:
##### Initial Development

### Current API:
In progress

### Development Status
  - [ ] Text Encryption

        Need to add "proper" key derivation
        Maybe take passphrase (padded if required), and hash it?
        Public api functions need to return values
        optimize derive/append IV functions by using pointers instead of copying
        storing encrypted text: HEX??
        include support for both hex and ascii encoded strings?

  - [ ] Decryption verification (how do we know when decryption succeeds vs fails?)

        Use a 32-bit CRC that we encrypt along with the plaintext

  - [ ] Make key and IV generation more secure

        Run raw key through a hashing function and use that as key
        Use a better PRNG
  - [ ] Text file Encryption

        Either read in text and encrypt it (and output cyphertext),
        or just build a universal method for all filetypes
  - [ ] Image file Encryption
  - [ ] Arbitrary filetype encryption?

        Could this be the universal mode of file encryption ie. all files encrypted the same way?
  - [ ] Tests

        Break out tests into proper individual methods, use asserts

##### Raw encrypted data:
   - First 16 byte block: initialization vector/nounce
        Not sure if we should be putting these "known bytes" at the beginning or end of the data.
   - Next `n` blocks: encrypted data, followed by 4 bytes CRC, then padded according to PKCS \#7.


Resources used:

  - Original AES ECB implementation from https://github.com/kokke/tiny-AES128-C, with modifications, as per the terms of the included src/lib/unlicense.txt files.

  - Implementation of cypher modes of operation is according to the NIST "Recommendation for Block Cypher Modes of Operation" (http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

  - Info on key derivation - NIST "Recommendation for Key Derivation
Using Pseudorandom Functions" (http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)

  - General mathematical background- Neal R. Wagner, "The Laws of Cryptography" (http://www.cs.utsa.edu/~wagner/lawsbookcolor/laws.pdf)

  - PCKS \#7 Specification - IETF Network Working Group (https://tools.ietf.org/html/rfc2315)

  - PKCS \#5 Specification - IETF Network Working Group (https://tools.ietf.org/html/rfc2898)

Project by Joel Ruhland - joel.ruhland@uwaterloo.ca
