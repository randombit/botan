/*
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2) || defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE)

   #include <botan/hash.h>
   #include <botan/hex.h>

   #include <botan/assert.h>
   #include <botan/sp_parameters.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/sp_address.h>
   #include <botan/internal/sp_fors.h>
   #include <botan/internal/sp_hash.h>

namespace Botan_Tests {

class SPHINCS_Plus_FORS_Test final : public Text_Based_Test {
   private:
      static Botan::Sphincs_Address read_address(std::span<const uint8_t> address_buffer) {
         BOTAN_ASSERT_NOMSG(address_buffer.size() == 32);

         std::array<uint32_t, 8> adrs;
         for(size_t i = 0; i < 8; ++i) {
            adrs[i] = Botan::load_be<uint32_t>(address_buffer.data(), i);
         }

         return Botan::Sphincs_Address(adrs);
      }

   public:
      SPHINCS_Plus_FORS_Test() :
            Text_Based_Test("pubkey/sphincsplus_fors.vec",
                            "SphincsParameterSet,Address,SecretSeed,PublicSeed,PublicKey,Msg,HashSig") {}

      bool skip_this_test(const std::string&, const VarMap& vars) override {
         [[maybe_unused]] auto params = Botan::Sphincs_Parameters::create(vars.get_req_str("SphincsParameterSet"));

   #if not defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE)
         if(params.hash_type() == Botan::Sphincs_Hash_Type::Shake256) {
            return true;
         }
   #endif

   #if not defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2)
         if(params.hash_type() == Botan::Sphincs_Hash_Type::Sha256) {
            return true;
         }
   #endif

         return false;
      }

      Test::Result run_one_test(const std::string&, const VarMap& vars) final {
         Test::Result result("SPHINCS+'s FORS");

         auto params = Botan::Sphincs_Parameters::create(vars.get_req_str("SphincsParameterSet"));

         const auto secret_seed = Botan::SphincsSecretSeed(vars.get_req_bin("SecretSeed"));
         const auto public_seed = Botan::SphincsPublicSeed(vars.get_req_bin("PublicSeed"));

         const auto hashed_message = Botan::SphincsHashedMessage(vars.get_req_bin("Msg"));

         // Depending on the SPHINCS+ configuration the resulting signature is
         // hashed either with SHA-3 or SHA-256 to reduce the inner dependencies
         // on other hash function modules.
         auto hash_algo_spec = [&]() -> std::string {
            if(params.hash_type() == Botan::Sphincs_Hash_Type::Shake256) {
               return "SHA-3(256)";
            } else {
               return "SHA-256";
            }
         }();
         auto hash = Botan::HashFunction::create(hash_algo_spec);

         auto hashes = Botan::Sphincs_Hash_Functions::create(params, public_seed);
         Botan::Sphincs_Address address = read_address(vars.get_req_bin("Address"));

         Botan::ForsSignature sig(params.fors_signature_bytes());

         auto pk = Botan::fors_sign_and_pkgen(sig, hashed_message, secret_seed, address, params, *hashes);

         const auto pk_ref = Botan::SphincsTreeNode(vars.get_req_bin("PublicKey"));
         result.test_is_eq("Derived public key", pk, pk_ref);

         const auto hashed_sig_ref = Botan::ForsSignature(vars.get_req_bin("HashSig"));
         result.test_is_eq("Signature result", unlock(hash->process(sig)), hashed_sig_ref.get());

         auto pk_from_sig = Botan::fors_public_key_from_signature(hashed_message, sig, address, params, *hashes);
         result.test_is_eq("Public key from signature", pk_from_sig, pk);

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "sphincsplus_fors", SPHINCS_Plus_FORS_Test);

}  // namespace Botan_Tests

#endif  // BOTAN_HAS_SPHINCS_PLUS
