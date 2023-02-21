load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
  name = "test_cbc",
  size = "small",
  srcs = ["cbc.cpp"],
  deps = [
    "@com_google_googletest//:gtest_main",
    "//src:crypter",
  ],
)

cc_test(
  name = "test_cfb",
  size = "small",
  srcs = ["cfb.cpp", "crypter_test.hpp"],
  deps = [
    "@com_google_googletest//:gtest_main",
    "//src:crypter",
  ],
)

cc_test(
  name = "test_ecb",
  size = "small",
  srcs = ["ecb.cpp", "crypter_test.hpp"],
  deps = [
    "@com_google_googletest//:gtest_main",
    "//src:crypter",

  ],
)

cc_test(
  name = "test_pcbc",
  size = "small",
  srcs = ["pcbc.cpp"],
  deps = [
    "@com_google_googletest//:gtest_main",
    "//src:crypter",
  ],
)

cc_test(
  name = "test_lib",
  size = "small",
  srcs = ["lib.cpp"],
  deps = [
    "@com_google_googletest//:gtest_main",
    "//src:crypter",
    "//lib:aes",
  ],
)


