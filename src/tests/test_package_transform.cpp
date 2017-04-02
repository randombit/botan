/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PACKAGE_TRANSFORM)
   #include <botan/package.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_PACKAGE_TRANSFORM)

class Package_Transform_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("Package transform");

         std::unique_ptr<Botan::BlockCipher> cipher(Botan::BlockCipher::create("AES-128"));
         std::vector<uint8_t> input = unlock(Test::rng().random_vec(Test::rng().next_byte()));
         std::vector<uint8_t> output(input.size() + cipher->block_size());

         // aont_package owns/deletes the passed cipher object, kind of a bogus API
         Botan::aont_package(Test::rng(),
                             cipher->clone(),
                             input.data(), input.size(),
                             output.data());

         std::vector<uint8_t> decoded(output.size() - cipher->block_size());
         Botan::aont_unpackage(cipher->clone(),
                               output.data(), output.size(),
                               decoded.data());
         result.test_eq("Package transform is reversible", decoded, input);

         output[0] ^= 1;
         Botan::aont_unpackage(cipher->clone(),
                               output.data(), output.size(),
                               decoded.data());
         result.test_ne("Bitflip breaks package transform", decoded, input);

         output[0] ^= 1;
         Botan::aont_unpackage(cipher->clone(),
                               output.data(), output.size(),
                               decoded.data());
         result.test_eq("Package transform is still reversible", decoded, input);

         // More tests including KATs would be useful for these functions

         return std::vector<Test::Result> {result};
         }
   };

BOTAN_REGISTER_TEST("package_transform", Package_Transform_Tests);

#endif

}
