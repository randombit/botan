/*
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_SPHINCS_PLUS) && defined (BOTAN_HAS_SHA2_32)

#include <botan/hash.h>
#include <botan/hex.h>

#include <botan/internal/loadstor.h>
#include <botan/assert.h>
#include <botan/internal/sp_address.h>
#include <botan/internal/sp_hash.h>
#include <botan/internal/sp_xmss.h>
#include <botan/sp_parameters.h>
#include <botan/sphincsplus.h>
#include <botan/secmem.h>


namespace Botan_Tests {

class SPHINCS_Plus_Test final : public Text_Based_Test
   {
   private:
      static Botan::Sphincs_Address read_address(std::span<const uint8_t> address_buffer)
         {
         BOTAN_ASSERT_NOMSG(address_buffer.size() == 32);

         std::array<uint32_t, 8> adrs;
         for(size_t i = 0; i < 8; ++i)
            {
            adrs[i] = Botan::load_be<uint32_t>(address_buffer.data(), i);
            }

         return Botan::Sphincs_Address(adrs);
         }

      void print_hex(unsigned char *data, size_t len) {
         char buf[3];
         for (size_t i = 0; i < len; i++) {
            sprintf(buf, "%02x", data[i]);
            printf("%s", buf);
         }
         printf("\n");
      }

   public:
      SPHINCS_Plus_Test()
         : Text_Based_Test("pubkey/sphincsplus.vec", "SphincsParameterSet,SecretSeed,PublicSeed,Root,Msg,SkPrf,OptRand,Signature")
      {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) final
         {
         Test::Result result("SPHINCS+ ");

         auto params = Botan::Sphincs_Parameters::create(vars.get_req_str("SphincsParameterSet"));

         const auto secret_seed = Botan::SphincsSecretSeed(vars.get_req_bin("SecretSeed"));
         const auto public_seed = Botan::SphincsPublicSeed(vars.get_req_bin("PublicSeed"));

         auto hashes = Botan::Sphincs_Hash_Functions::create(params);

         std::vector<uint8_t> out_root(params.n());

         Botan::xmss_gen_root(out_root, params, public_seed, secret_seed, *hashes);
         const std::vector<uint8_t> root_ref = vars.get_req_bin("Root");
         result.test_is_eq("Sphincs+ root", out_root, root_ref);

         const std::vector<uint8_t> msg = vars.get_req_bin("Msg");
         Botan::secure_vector<uint8_t> sk_prf = Botan::lock(vars.get_req_bin("SkPrf"));

         const std::vector<uint8_t> sig_ref = vars.get_req_bin("Signature");
         const std::vector<uint8_t> opt_rand = vars.get_req_bin("OptRand");

         auto sig = Botan::sphincsplus_sign(msg,
                                                      secret_seed.get(),
                                                       sk_prf,
                                                     public_seed.get(),
                                                     opt_rand,
                                                          root_ref,
                                                                   params);

         result.test_is_eq("Sphincs+ Signature", sig, sig_ref);

         if(result.tests_failed()){
            print_hex(sig.data(), sig.size());
            int breakpoint_dummy;
         }


         return result;
         }

      bool skip_this_test(const std::string&,
                          const VarMap& vars) override
         {
         auto params = Botan::Sphincs_Parameters::create(vars.get_req_str("SphincsParameterSet"));
         return Botan::HashFunction::create(params.hash_name()) == nullptr;
         }
   };

   BOTAN_REGISTER_TEST("pubkey", "sphincsplus", SPHINCS_Plus_Test);

}  // namespace Botan_Tests

#endif  // BOTAN_HAS_SPHINCS_PLUS
