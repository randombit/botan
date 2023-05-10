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
#include <botan/internal/sp_wots.h>
#include <botan/sp_parameters.h>

namespace Botan_Tests {

class SPHINCS_Plus_WOTS_Test final : public Text_Based_Test
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

    // Temp - delete me
    static void print_hex(unsigned char *data, size_t len) {
        char buf[3];
        for (size_t i = 0; i < len; i++) {
            sprintf(buf, "%02x", data[i]);
            printf("%s", buf);
        }
        printf("\n");
    }


   public:
      SPHINCS_Plus_WOTS_Test()
         : Text_Based_Test("pubkey/sphincsplus_wots.vec", "SphincsParameterSet,Address,SecretSeed,PublicSeed,HashedWotsPk,WotsPk,Msg,WotsSig")
      {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) final
         {
         Test::Result result("SPHINCS+'s WOTS+");

         auto params = Botan::Sphincs_Parameters::create(vars.get_req_str("SphincsParameterSet"));

         const auto secret_seed = Botan::SphincsSecretSeed(vars.get_req_bin("SecretSeed"));
         const auto public_seed = Botan::SphincsPublicSeed(vars.get_req_bin("PublicSeed"));

         const auto hashed_message = Botan::SphincsHashedMessage(vars.get_req_bin("Msg"));

         Botan::Sphincs_Address address = read_address(vars.get_req_bin("Address"));


         const auto wots_sig_ref = Botan::WotsSignature(vars.get_req_bin("WotsSig"));


         auto hashes = Botan::Sphincs_Hash_Functions::create(params);

         Botan::WotsPublicKey wots_pk_from_sig = Botan::wots_public_key_from_signature(hashed_message,
                                                                            wots_sig_ref,
                                                                                      public_seed,
                                                                                      address,
                                                                                      params,
                                                                                *hashes);

         const auto wots_pk_ref = Botan::WotsPublicKey(vars.get_req_bin("WotsPk"));

         std::vector<uint8_t> sig_out(params.n() * params.wots_len());
         std::vector<uint8_t> hashed_pk_out(params.n());

         auto wots_steps = Botan::chain_lengths(hashed_message, params);

         auto leaf_addr = Botan::Sphincs_Address::as_subtree_from(address);
         auto pk_addr = Botan::Sphincs_Address::as_subtree_from(address);

         pk_addr.set_type(Botan::Sphincs_Address_Type::WotsPublicKeyCompression);

         wots_gen_leaf_spec(sig_out,
                  hashed_pk_out,
                  secret_seed,
                  public_seed,
                  0,
                  0,
                  wots_steps.get(),
                  leaf_addr,
                  pk_addr,
                  params,
                  *hashes);




         result.test_is_eq("WOTS+ signature generation", sig_out, wots_sig_ref.get());

         auto hashed_pk_ref = vars.get_req_bin("HashedWotsPk");
         result.test_is_eq("WOTS+ public key generation", hashed_pk_out, hashed_pk_ref);

         result.test_is_eq("WOTS+ public key from signature", wots_pk_from_sig, wots_pk_ref);

         if(result.tests_failed() > 0){
            int x = 0; // Dummy
            print_hex(wots_pk_from_sig.data(), wots_pk_from_sig.size());
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

   BOTAN_REGISTER_TEST("pubkey", "sphincsplus_wots", SPHINCS_Plus_WOTS_Test);

}  // namespace Botan_Tests

#endif  // BOTAN_HAS_SPHINCS_PLUS
