#include <stdint.h>

class Tests {

  static void test_encrypt_ecb_verbose(void);
  static void test_encrypt_ecb(void);
  static void test_decrypt_ecb(void);

public:
  static void phex(uint8_t* str);
  static void runTests(void);
};
