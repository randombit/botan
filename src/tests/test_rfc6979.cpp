/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
  #include <botan/rfc6979.h>
  #include <botan/hex.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_RFC6979_GENERATOR)

class RFC6979_KAT_Tests : public Text_Based_Test
   {
   public:
      RFC6979_KAT_Tests() : Text_Based_Test("rfc6979.vec",
                                            {"Q", "X", "H", "K"}) {}

      Test::Result run_one_test(const std::string& hash, const VarMap& vars) override
         {
         const BigInt Q = get_req_bn(vars, "Q");
         const BigInt X = get_req_bn(vars, "X");
         const BigInt H = get_req_bn(vars, "H");
         const BigInt K = get_req_bn(vars, "K");

         Test::Result result("RFC 6979 nonce generation");
         result.test_eq("vector matches", Botan::generate_rfc6979_nonce(X, Q, H, hash), K);

         Botan::RFC6979_Nonce_Generator gen(hash, Q, X);

         result.test_eq("vector matches", gen.nonce_for(H), K);
         result.test_ne("vector matches", gen.nonce_for(H+1), K);
         result.test_eq("vector matches", gen.nonce_for(H), K);

         return result;
         }
   };

BOTAN_REGISTER_TEST("rfc6979", RFC6979_KAT_Tests);

#endif

}

}
