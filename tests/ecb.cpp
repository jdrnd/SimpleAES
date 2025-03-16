#include <gtest/gtest.h>

#include "src/crypter.h"

#include "crypter_test.hpp"

TEST_F(CrypterTest, TEST_ECB) {
  auto encrypted_data = Crypter::ECB_encrypt(input_data,
                                             passphrase);
  EXPECT_EQ(encrypted_data.size(), 80);

  auto plaintext_data = Crypter::ECB_decrypt(encrypted_data, passphrase);
  (void) plaintext_data;
}
