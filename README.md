# SimpleAES Library

This library is designed to provide an easy interface to AES encryption.

### Project Status:
##### Initial Development

### Current API:
In progress

### Development Status
  - [ ] Text Encryption

        Need to add "proper" key derrivation
        Maybe take passphrase (padded if required), and hash it?
        Public api functions need to return values
        optimize derive/append IV functions by using pointers instead of copying
        storing encrypted text: HEX??
        include support for both hex and ascii encoded strings

  - [ ] Decryption verification (how do we know when decryption suceeds vs fails?)

        Looking into magic bits or a checksum here...
        HMAC?? https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
        This?? https://en.wikipedia.org/wiki/Cyclic_redundancy_check
  - [ ] Make key and IV generation more secure

        Run raw key through a hashing function and use that as key
        Use a better PRNG
  - [ ] Text file Encryption

        Either read in text and encrypt it (and output cyphertext),
        or just build a universal method for all filetypes
  - [ ] Image file Encryption
  - [ ] Arbitrary filetype encryption?

        Could this be the universal mode of fileencryption ie. all files encrypted the same way?
  - [ ] Tests

        Break out tests into proper individual methods, use asserts

##### Raw encrypted data:
   - First 16 byte block: initialization vector
   - (TODO: next 16 byte block: checksum or magic bytes for verification)

        Not sure if whe should be putting these "known bytes" at the beginning or end of the data.
   - Next `n` blocks: encrypted data


Original AES implimentation from https://github.com/kokke/tiny-AES128-C, with modifications, as per the terms of the included unlicense.txt files.

Project by Joel Ruhland - joel.ruhland@uwaterloo.ca
