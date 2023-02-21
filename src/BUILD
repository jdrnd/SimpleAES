cc_library(
  name = "crypter",
  hdrs = [
    "crypter.h",
    "types.h",
    "key.hpp"
  ],
  srcs = [
    "crypter.cpp",
    "helpers.cpp",
    "utils.cpp",
    "key.cpp",
  ],
  deps = [
    "//lib:aes",
    "@com_google_absl//absl/types:span"
  ],
  visibility = ["//visibility:public"],
)