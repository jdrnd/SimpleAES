#include <gtest/gtest.h>

#include "crypter_test.hpp"
#include "src/crypter.h"

TEST_F(CrypterTest, TEST_CFB) {
 printf("0\n");
  auto encrypted_data = Crypter::CFB_encrypt(input_data,
                                             passphrase);
  
  EXPECT_EQ(encrypted_data.size(), 96);

  uint8_t* plaintext_data = Crypter::CFB_decrypt(absl::MakeSpan(encrypted_data.data(), 96), passphrase);
  printf("3\n");
  (void) plaintext_data;
}