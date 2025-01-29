/*
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_SPHINCS_PLUS_COMMON)

   #include <botan/hash.h>
   #include <botan/hex.h>

   #include <botan/assert.h>
   #include <botan/sp_parameters.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/sp_address.h>
   #include <botan/internal/sp_hash.h>
   #include <botan/internal/sp_wots.h>

namespace Botan_Tests {

class SPHINCS_Plus_WOTS_Test final : public Text_Based_Test {
   private:
      static std::pair<Botan::Sphincs_Address, Botan::TreeNodeIndex> read_address_and_leaf_idx(
         std::span<const uint8_t> address_buffer) {
         BOTAN_ASSERT_NOMSG(address_buffer.size() == 32);

         std::array<uint32_t, 8> adrs;
         for(size_t i = 0; i < 8; ++i) {
            adrs[i] = Botan::load_be<uint32_t>(address_buffer.data(), i);
         }

         return std::make_pair(Botan::Sphincs_Address(adrs), Botan::TreeNodeIndex(adrs[5]));
      }

   public:
      SPHINCS_Plus_WOTS_Test() :
            Text_Based_Test("pubkey/sphincsplus_wots.vec",
                            "SphincsParameterSet,Address,SecretSeed,PublicSeed,HashedWotsPk,Msg,HashedWotsSig") {}

      bool skip_this_test(const std::string&, const VarMap& vars) override {
         [[maybe_unused]] auto params = Botan::Sphincs_Parameters::create(vars.get_req_str("SphincsParameterSet"));
         return !params.is_available();
      }

      Test::Result run_one_test(const std::string&, const VarMap& vars) final {
         Test::Result result("SLH-DSA's WOTS+");

         auto params = Botan::Sphincs_Parameters::create(vars.get_req_str("SphincsParameterSet"));

         auto [address, leaf_idx] = read_address_and_leaf_idx(vars.get_req_bin("Address"));
         const auto secret_seed = Botan::SphincsSecretSeed(vars.get_req_bin("SecretSeed"));
         const auto public_seed = Botan::SphincsPublicSeed(vars.get_req_bin("PublicSeed"));
         auto hashed_pk_ref = Botan::SphincsTreeNode(vars.get_req_bin("HashedWotsPk"));
         const auto root_to_sign = Botan::SphincsTreeNode(vars.get_req_bin("Msg"));
         const auto hashed_wots_sig_ref = Botan::WotsSignature(vars.get_req_bin("HashedWotsSig"));

         auto hashes = Botan::Sphincs_Hash_Functions::create(params, public_seed);

         // Depending on the SLH-DSA's configuration the resulting WOTS+ signature is
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

         if(!hash) {
            result.test_note("Skipping due to missing hash function");
            return result;
         }

         // Addresses used for signing
         auto leaf_addr = Botan::Sphincs_Address::as_subtree_from(address);
         auto pk_addr_sign_and_pkgen = Botan::Sphincs_Address::as_subtree_from(address).set_type(
            Botan::Sphincs_Address_Type::WotsPublicKeyCompression);

         // Address used for hashing the WOTS+ public key
         auto pk_addr_pk_from_sig = Botan::Sphincs_Address::as_subtree_from(address).set_type(
            Botan::Sphincs_Address_Type::WotsPublicKeyCompression);
         pk_addr_pk_from_sig.set_keypair_address(leaf_idx);

         // Prepare the message
         auto wots_steps = Botan::chain_lengths(root_to_sign, params);

         // Test: WOTS+ Signature and Public Key Generation
         Botan::WotsSignature sig_out(params.n() * params.wots_len());
         Botan::SphincsTreeNode hashed_pk_out(params.n());
         wots_sign_and_pkgen(Botan::StrongSpan<Botan::WotsSignature>(sig_out),
                             Botan::StrongSpan<Botan::SphincsTreeNode>(hashed_pk_out),
                             secret_seed,
                             leaf_idx,
                             leaf_idx,
                             wots_steps,
                             leaf_addr,
                             pk_addr_sign_and_pkgen,
                             params,
                             *hashes);

         result.test_is_eq("WOTS+ signature generation", hash->process(sig_out), hashed_wots_sig_ref.get());
         result.test_is_eq("WOTS+ public key generation", hashed_pk_out, hashed_pk_ref);

         // Test: Create PK from signature (Verification)
         Botan::WotsPublicKey wots_pk_from_sig =
            Botan::wots_public_key_from_signature(root_to_sign, sig_out, address, params, *hashes);

         // The WOTS+ PK is hashed like for creating a leaf.
         result.test_is_eq("WOTS+ public key from signature",
                           hashes->T<Botan::SphincsTreeNode>(pk_addr_pk_from_sig, wots_pk_from_sig),
                           hashed_pk_ref);

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "sphincsplus_wots", SPHINCS_Plus_WOTS_Test);

}  // namespace Botan_Tests

#endif  // BOTAN_HAS_SPHINCS_PLUS_COMMON
