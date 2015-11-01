/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
  #include <botan/pubkey.h>
  #include "test_rng.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_DSA)

class DSA_KAT_Tests : public Text_Based_Test
   {
   public:
      DSA_KAT_Tests() : Text_Based_Test(Test::data_file("pubkey/dsa.vec"), {"P", "Q", "G", "X", "Hash", "Msg", "Signature"}, {}, false) {}

      size_t soak_level() const { return 5; }

      void check_invalid_signatures(Result& result,
                                    Botan::PK_Verifier& verifier,
                                    Botan::RandomNumberGenerator& rng,
                                    const std::vector<byte>& message,
                                    const std::vector<byte>& signature) const
         {
         const std::vector<byte> zero_sig(signature.size());
         result.test_eq("all zero signature invalid", verifier.verify_message(message, zero_sig), false);

         std::vector<byte> bad_sig = signature;
         for(size_t i = 0; i <= soak_level(); ++i)
            {
            size_t offset = rng.get_random<uint16_t>() % bad_sig.size();
            bad_sig[offset] ^= rng.next_nonzero_byte();

            if(!result.test_eq("incorrect signature invalid", verifier.verify_message(message, bad_sig), false))
               {
               result.test_note("Accepted invalid signature " + Botan::hex_encode(bad_sig));
               }
            }
         }

      Test::Result run_one_test(const std::string& algo,
                                const std::map<std::string, std::string>& vars) override
         {
         const std::vector<uint8_t> message   = get_req_bin(vars, "Msg");
         const std::vector<uint8_t> signature = get_req_bin(vars, "Signature");

         const BigInt p = get_req_bn(vars, "P");
         const BigInt q = get_req_bn(vars, "Q");
         const BigInt g = get_req_bn(vars, "G");
         const BigInt x = get_req_bn(vars, "X");

         const std::string hash = get_req_str(vars, "Hash");
         const std::vector<uint8_t> msg = get_req_bin(vars, "Msg");

         Botan::RandomNumberGenerator& rng = test_rng();

         Test::Result result("DSA/" + hash);

         const Botan::DL_Group group(p, q, g);
         const Botan::DSA_PrivateKey privkey(rng, group, x);
         const Botan::DSA_PublicKey pubkey = privkey;
         const std::string padding = "EMSA1(" + hash + ")";

         Botan::PK_Verifier verifier(pubkey, padding);
         Botan::PK_Signer signer(privkey, padding);

         result.test_eq("correct signature valid", verifier.verify_message(message, signature), true);

         const std::vector<byte> generated_signature = signer.sign_message(message, rng);
         result.test_eq("generated signature valid", verifier.verify_message(message, generated_signature), true);
         result.test_eq("generated signature matches KAT", generated_signature, signature);

         check_invalid_signatures(result, verifier, rng, message, signature);

         return result;
         }
   };

BOTAN_REGISTER_TEST("dsa", DSA_KAT_Tests);

#endif

}

}

size_t test_dsa()
   {
   using namespace Botan_Tests;

   std::vector<Test::Result> results = Test::run_test("dsa");

   std::string report;
   size_t fail_cnt = 0;
   Test::summarize(results, report, fail_cnt);

   std::cout << report;
   return fail_cnt;
   }
