/*
* (C) 2015,2016,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FUZZER_DRIVER_H_
#define BOTAN_FUZZER_DRIVER_H_

#include <botan/chacha_rng.h>
#include <botan/exceptn.h>
#include <iostream>
#include <stdint.h>
#include <stdlib.h>  // for setenv
#include <vector>

static const size_t max_fuzzer_input_size = 8192;

extern void fuzz(std::span<const uint8_t> in);

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t in[], size_t len);

extern "C" int LLVMFuzzerInitialize(int*, char***) {
   /*
   * This disables the mlock pool, as overwrites within the pool are
   * opaque to ASan or other instrumentation.
   */
   ::setenv("BOTAN_MLOCK_POOL_SIZE", "0", 1);
   return 0;
}

// Called by main() in libFuzzer or in main for AFL below
extern "C" int LLVMFuzzerTestOneInput(const uint8_t in[], size_t len) {
   if(len <= max_fuzzer_input_size) {
      fuzz(std::span<const uint8_t>(in, len));
   }
   return 0;
}

// Some helpers for the fuzzer jigs

inline std::shared_ptr<Botan::RandomNumberGenerator> fuzzer_rng_as_shared() {
   static std::shared_ptr<Botan::ChaCha_RNG> rng =
      std::make_shared<Botan::ChaCha_RNG>(Botan::secure_vector<uint8_t>(32));
   return rng;
}

inline Botan::RandomNumberGenerator& fuzzer_rng() {
   return *fuzzer_rng_as_shared();
}

#define FUZZER_WRITE_AND_CRASH(expr)                                             \
   do {                                                                          \
      std::cerr << expr << " @ Line " << __LINE__ << " in " << __FILE__ << "\n"; \
      abort();                                                                   \
   } while(0)

#define FUZZER_ASSERT_EQUAL(x, y)                                                        \
   do {                                                                                  \
      if(x != y) {                                                                       \
         FUZZER_WRITE_AND_CRASH(#x << " = " << x << " != " << #y << " = " << y << "\n"); \
      }                                                                                  \
   } while(0)

#define FUZZER_ASSERT_TRUE(e)                                         \
   do {                                                               \
      if(!(e)) {                                                      \
         FUZZER_WRITE_AND_CRASH("Expression " << #e << " was false"); \
      }                                                               \
   } while(0)

#if defined(BOTAN_FUZZER_IS_AFL) || defined(BOTAN_FUZZER_IS_TEST)

   /* Stub for AFL */

   #if defined(BOTAN_FUZZER_IS_AFL) && !defined(__AFL_COMPILER)
      #error "Build configured for AFL but not being compiled by AFL compiler"
   #endif

   #if defined(BOTAN_FUZZER_IS_TEST)

      #include <fstream>

namespace {

int fuzz_files(char* files[]) {
   for(size_t i = 0; files[i]; ++i) {
      std::ifstream in(files[i]);

      if(in.good()) {
         std::vector<uint8_t> buf(max_fuzzer_input_size);
         in.read(reinterpret_cast<char*>(buf.data()), buf.size());
         const size_t got = in.gcount();
         buf.resize(got);
         buf.shrink_to_fit();

         LLVMFuzzerTestOneInput(buf.data(), got);
      }
   }

   return 0;
}

}  // namespace

   #endif

int main(int argc, char* argv[]) {
   LLVMFuzzerInitialize(&argc, &argv);

   #if defined(BOTAN_FUZZER_IS_TEST)
   if(argc > 1) {
      return fuzz_files(&argv[1]);
   }
   #endif

   #if defined(__AFL_LOOP)
   while(__AFL_LOOP(1000))
   #endif
   {
      std::vector<uint8_t> buf(max_fuzzer_input_size);
      std::cin.read(reinterpret_cast<char*>(buf.data()), buf.size());
      const size_t got = std::cin.gcount();

      buf.resize(got);
      buf.shrink_to_fit();

      LLVMFuzzerTestOneInput(buf.data(), got);
   }
}

#elif defined(BOTAN_FUZZER_IS_KLEE)

   #include <klee/klee.h>

int main(int argc, char* argv[]) {
   LLVMFuzzerInitialize(&argc, &argv);

   uint8_t input[max_fuzzer_input_size] = {0};
   klee_make_symbolic(&input, sizeof(input), "input");

   size_t input_len = klee_range(0, sizeof(input), "input_len");

   LLVMFuzzerTestOneInput(input, input_len);
}

#endif

#endif
