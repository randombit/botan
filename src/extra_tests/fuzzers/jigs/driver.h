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
#include <botan/rng.h>
#include <botan/chacha.h>

using namespace Botan;

extern void fuzz(const uint8_t in[], size_t len);

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
   {
   /*
   * This disables the mlock pool, as overwrites within the pool are
   * opaque to ASan or other instrumentation.
   */
   ::setenv("BOTAN_MLOCK_POOL_SIZE", "0", 1);
   return 0;
   }

// Called by main() in libFuzzer or in main for AFL below
extern "C" int LLVMFuzzerTestOneInput(const uint8_t in[], size_t len)
   {
   fuzz(in, len);
   return 0;
   }

#if defined(INCLUDE_AFL_MAIN)

// Read stdin for AFL

int main(int argc, char* argv[])
   {
   const size_t max_read = 4096;

   LLVMFuzzerInitialize();

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

// Some helpers for the fuzzer jigs

inline Botan::RandomNumberGenerator& fuzzer_rng()
   {
   class ChaCha20_RNG : public Botan::RandomNumberGenerator
      {
      public:
         std::string name() const override { return "ChaCha20_RNG"; }
         void clear() override { /* ignored */ }

         void randomize(uint8_t out[], size_t len) override
            {
            Botan::clear_mem(out, len);
            m_chacha.cipher1(out, len);
            }

         bool is_seeded() const override { return true; }

         void add_entropy(const uint8_t[], size_t) override { /* ignored */ }

         ChaCha20_RNG()
            {
            std::vector<uint8_t> seed(32, 0x82);
            m_chacha.set_key(seed);
            }

      private:
         Botan::ChaCha m_chacha;
      };

   static ChaCha20_RNG rng;
   return rng;
   }

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

#endif
