#include <stdint.h>

#ifndef TEST_TEST_H
#define TEST_TEST_H

class Tests {

    // TODO refactor to use a real test framework
  static void test_encrypt_ecb_verbose(void);
  static void test_encrypt_ecb(void);
  static void test_decrypt_ecb(void);

  static void test_ecb(void);
  static void test_cbc(void);
  static void test_pcbc(void);
  static void test_cfb(void);

  static void test_crc(void);
  static void test_key_derivation(void);

public:
  static void phex(uint8_t* str);
  static void runTests(void);
};

#endif
