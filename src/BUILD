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
    "@abseil-cpp//absl/types:span"
  ],
  visibility = ["//visibility:public"],
)