/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_RW)
  #include <botan/rw.h>
  #include <botan/pubkey.h>
  #include "test_pubkey.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_RW)

class RW_KAT_Tests : public Text_Based_Test
   {
   public:
      RW_KAT_Tests() : Text_Based_Test(Test::data_file("pubkey/rw_sig.vec"), {"E", "P", "Q", "Msg", "Signature"}, {}, false) {}

      Test::Result run_one_test(const std::string&,
                                const std::map<std::string, std::string>& vars) override
         {
         const std::vector<uint8_t> message   = get_req_bin(vars, "Msg");
         const std::vector<uint8_t> signature = get_req_bin(vars, "Signature");

         const BigInt p = get_req_bn(vars, "P");
         const BigInt q = get_req_bn(vars, "Q");
         const BigInt e = get_req_bn(vars, "E");

         Test::Result result("Rabin-Williams");

         const Botan::RW_PrivateKey privkey(Test::rng(), p, q, e);
         const Botan::RW_PublicKey pubkey = privkey;
         const std::string padding = "EMSA2(SHA-1)";

         Botan::PK_Signer signer(privkey, padding);
         Botan::PK_Verifier verifier(pubkey, padding);

         const std::vector<byte> generated_signature = signer.sign_message(message, Test::rng());
         result.test_eq("generated signature matches KAT", generated_signature, signature);

         result.test_eq("generated signature valid", verifier.verify_message(message, generated_signature), true);
         check_invalid_signatures(result, verifier, message, signature);
         result.test_eq("correct signature valid", verifier.verify_message(message, signature), true);

         return result;
         }
   };

class RW_Verify_Tests : public Text_Based_Test
   {
   public:
      RW_Verify_Tests() : Text_Based_Test(Test::data_file("pubkey/rw_verify.vec"), {"E", "N", "Msg", "Signature"}, {}, false) {}

      Test::Result run_one_test(const std::string&,
                                const std::map<std::string, std::string>& vars) override
         {
         const std::vector<uint8_t> message   = get_req_bin(vars, "Msg");
         const std::vector<uint8_t> signature = get_req_bin(vars, "Signature");

         const BigInt n = get_req_bn(vars, "N");
         const BigInt e = get_req_bn(vars, "E");

         Test::Result result("Rabin-Williams Verification");

         const Botan::RW_PublicKey pubkey(n, e);
         const std::string padding = "EMSA2(SHA-1)";

         Botan::PK_Verifier verifier(pubkey, padding);

         result.test_eq("correct signature valid", verifier.verify_message(message, signature), true);

         check_invalid_signatures(result, verifier, message, signature);

         return result;
         }
   };

BOTAN_REGISTER_TEST("rw_kat", RW_KAT_Tests);
BOTAN_REGISTER_TEST("rw_verify", RW_Verify_Tests);

#endif

}

}

size_t test_rw()
   {
   using namespace Botan_Tests;

   return basic_error_report("rw_kat") + basic_error_report("rw_verify");
   }
