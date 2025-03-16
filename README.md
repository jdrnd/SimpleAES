# SimpleAES Library
##### Project by Joel Ruhland - joel@joelruhland.net

This library is designed to provide an easy interface to 128-bit AES encryption.

Building off an extremely minimal AES ECB implementation, this library strives to do the following (none of which is provided by the ECB code):
  - [x] Protect against memory out of bounds errors
  - [x] Allow for inputs of arbitrary length, not just 16 bytes
  - [x] Provide message authentication and integrity verification
  - [x] Detect when an incorrect key is being used (rather than spitting out gibberish)
  - [ ] Implement the following modes of operation
    - [x] CBC
    - [x] PCBC
    - [x] CFB
    - [ ] OFB
    - [ ] CTR 
 
   

This code is purely experimental. NEVER use this in any system which requires actual security. Personally I recommend the Salt library (https://nacl.cr.yp.to/index.html), but I am not a cryptographer (see license disclaimer). 

### Project Status:
##### Initial Development

### Current API:
In progress

### Development TODO (in rough order of priority)
  - [ ] Refactor project API
  - [ ] Remove shared/generic code into separate methods, use enum to determine encryption type
  - [ ] Return a custom struct containing data and metadata
  - [ ] Move to a real key derivation function
  - [ ] Use a CSPRNG instead of the language's builtin RNG  ¯\_(ツ)_/¯
  - [ ] File Encryption
  - [x] Move to the Google C++ testing framework (https://github.com/google/googletest)
  - [ ] Helper functions to en/decrypt other C++ data types/structures
  - [x] Decryption verification (how do we know when decryption succeeds vs fails?)
    - Uses a 32-bit CRC that we encrypt along with the plaintext
  - [x] ECB support for arbitrary length
    - [x] PKCS #7 padding
  - [x] CBC mode
    - [x] IV generation/extraction
  - [x] PCBC mode
  - [x] CFB mode
  - [ ] CTR mode
  - [ ] OFB mode

##### Raw encrypted data:
(Note this will be refactored soon)
   - First 16 byte block: initialization vector/nounce
        Not sure if we should be putting these "known bytes" at the beginning or end of the data.
   - Rest of message: encrypted data, followed by 4 bytes CRC, then padded according to PKCS \#7.


### Resources:

  - Original AES ECB implementation from https://github.com/kokke/tiny-AES128-C, with modifications, as per the terms of the included `lib/unlicense.txt` file.

  - Implementation of cypher modes of operation is according to the NIST "Recommendation for Block Cypher Modes of Operation" (http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

  - Info on key derivation - NIST "Recommendation for Key Derivation
Using Pseudorandom Functions" (http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)

  - General mathematical background- Neal R. Wagner, "The Laws of Cryptography" (http://www.cs.utsa.edu/~wagner/lawsbookcolor/laws.pdf)

  - PCKS \#7 Specification - IETF Network Working Group (https://tools.ietf.org/html/rfc2315)

  - PKCS \#5 Specification - IETF Network Working Group (https://tools.ietf.org/html/rfc2898)
  
  - Google C++ Style Guide (https://google.github.io/styleguide/cppguide.html)


#### Useful Notes
To print a buffer of length 96 as hex using gdb: `x /96xb buffer`

### License 

Licensed under the MIT License, see include `LICENSE` file.
