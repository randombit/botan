/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef FUZZER_DRIVER_H_
#define FUZZER_DRIVER_H_

#include <stdint.h>
#include <iostream>
#include <vector>
#include <stdlib.h> // for setenv
#include <botan/exceptn.h>

using namespace Botan;

void fuzz(const uint8_t in[], size_t len);

void fuzzer_init()
   {
   /*
   * This disables the mlock pool, as overwrites within the pool are
   * opaque to ASan or other instrumentation.
   */
   ::setenv("BOTAN_MLOCK_POOL_SIZE", "0", 1);
   }

#if defined(USE_LLVM_FUZZER)

// Called by main() in libFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t in[], size_t len)
   {
   fuzz(in, len);
   return 0;
   }

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  fuzzer_init();
  return 0;
}

#else

// Read stdin for AFL

int main(int argc, char* argv[])
   {
   const size_t max_read = 4096;

   fuzzer_init();

#if defined(__AFL_LOOP)
   while(__AFL_LOOP(1000))
#endif
      {
      std::vector<uint8_t> buf(max_read);
      std::cin.read((char*)buf.data(), buf.size());
      size_t got = std::cin.gcount();

      buf.resize(got);
      buf.shrink_to_fit();

      fuzz(buf.data(), got);
      }
   }

#endif

#endif

// Some helpers for the fuzzer jigs

#define FUZZER_ASSERT_EQUAL(x, y) do {                                  \
   if(x != y) {                                                         \
      std::cerr << #x << " = " << x << " !=\n" << #y << " = " << y         \
                << " at " << __LINE__ << ":" << __FILE__ << std::endl;     \
      abort();                                                          \
} } while(0)

#define FUZZER_ASSERT_TRUE(e)                                           \
   do {                                                                 \
   if(!(e)) {                                                           \
   std::cerr << "Expression " << #e << " was false at "                 \
             << __LINE__ << ":" << __FILE__ << std::endl;               \
   abort();                                                             \
   } } while(0)
