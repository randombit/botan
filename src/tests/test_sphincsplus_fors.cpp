/*
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "botan/assert.h"
#include "botan/internal/sp_address.h"
#include "botan/internal/sp_hash.h"
#include "botan/sp_parameters.h"
#include "tests.h"

#if defined(BOTAN_HAS_SPHINCS_PLUS)

#include <botan/hash.h>
#include <botan/hex.h>

#include <iostream>

#include <botan/internal/sp_fors.h>
#include <botan/internal/loadstor.h>

namespace Botan_Tests {

class SPHINCS_Plus_FORS_Test final : public Text_Based_Test
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

   public:
      SPHINCS_Plus_FORS_Test()
         : Text_Based_Test("pubkey/sphincsplus_fors.vec", "SphincsParameterSet,Address,SecretSeed,PublicSeed,PublicKey,Msg,Signature")
      {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) final
         {
         Test::Result result("SPHINCS+'s FORS");

         auto params = Botan::Sphincs_Parameters::create(vars.get_req_str("SphincsParameterSet"));

         const auto secret_seed = Botan::SphincsSecretSeed(vars.get_req_bin("SecretSeed"));
         const auto public_seed = Botan::SphincsPublicSeed(vars.get_req_bin("PublicSeed"));

         const auto hashed_message = Botan::SphincsHashedMessage(vars.get_req_bin("Msg"));

         auto hash = Botan::HashFunction::create_or_throw(params.hash_name());

         auto hashes = Botan::Sphincs_Hash_Functions::create(params);
         Botan::Sphincs_Address address = read_address(vars.get_req_bin("Address"));
         auto [ pk, sig ] = Botan::fors_sign(hashed_message,
                                             secret_seed,
                                             public_seed,
                                             address,
                                             params,
                                             *hashes);

         const auto pk_ref = Botan::ForsPublicKey(vars.get_req_bin("PublicKey"));
         result.test_is_eq("Derived public key", pk, pk_ref);

         const auto sig_ref = Botan::ForsSignature(vars.get_req_bin("Signature"));
         result.test_is_eq("Signature result", sig, sig_ref);

         std::cout << Botan::hex_encode(pk) << std::endl;
         std::cout << Botan::hex_encode(pk_ref) << std::endl;

         auto pk_from_sig = Botan::fors_public_key_from_signature(hashed_message,
                                                                  sig,
                                                                  public_seed,
                                                                  address,
                                                                  params,
                                                                  *hashes);
         result.test_is_eq("Public key from signature", pk_from_sig, pk);

         if(result.tests_failed() > 0){
            int x = 0; // Dummy
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

static Test::Result test_fors_message_to_indices()
   {
   auto params = Botan::Sphincs_Parameters::create(Botan::Sphincs_Parameter_Set::Sphincs128Fast, Botan::Sphincs_Hash_Type::Sha256);
   auto indices = Botan::fors_message_to_indices(
      Botan::hex_decode("5507795cff3b0fc715e3fe3bf1d47ddbc66d6f48aa664094be3ae0c852a9f7f9137923d8b9b646e6d1c5d92916a8619009e5907d56c77b87c7001ff8e27dbf39997b4453176648fdcc9742d3a3175beda8229d059a6e4f157bbe43a99d7d20891a603fb626891401250945a5cc504e17ee80109e9fa52d2adbe9570917362ff4c3800d822a9c6045bf6dd17cfa7db110593e48420f503a7cf85045d07dbdf672079092e3b6ced3342570dfb3a68685790a125800779ea7991effc0f7890586e6bfedbe1c31506a7df180041c259c50cd6349428b2d3255a876cb7f0786e38bdcd3b157e59191a7c663b4b7482abb0bcf93a7a0c59456473eef0d470b3b1218238c450c5523fd057fbbc926717719f2e1"),
      params);

   Test::Result result("FORS message to indices");
   if(result.test_eq("number of indices", indices.size(), params.k()))
      {
      result.test_eq_sz("idx #0", indices.get().at(0), 341);
      result.test_eq_sz("idx #1", indices.get().at(1), 131);
      result.test_eq_sz("idx #2", indices.get().at(2), 286);
      result.test_eq_sz("idx #3", indices.get().at(3), 491);
      result.test_eq_sz("idx #4", indices.get().at(4), 447);
      result.test_eq_sz("idx #5", indices.get().at(5), 121);
      result.test_eq_sz("idx #6", indices.get().at(6), 284);
      result.test_eq_sz("idx #7", indices.get().at(7), 43);
      result.test_eq_sz("idx #8", indices.get().at(8), 227);
      result.test_eq_sz("idx #9", indices.get().at(9), 511);
      result.test_eq_sz("idx #10", indices.get().at(10), 78);
      result.test_eq_sz("idx #11", indices.get().at(11), 158);
      result.test_eq_sz("idx #12", indices.get().at(12), 477);
      result.test_eq_sz("idx #13", indices.get().at(13), 219);
      result.test_eq_sz("idx #14", indices.get().at(14), 283);
      result.test_eq_sz("idx #15", indices.get().at(15), 219);
      result.test_eq_sz("idx #16", indices.get().at(16), 111);
      result.test_eq_sz("idx #17", indices.get().at(17), 292);
      result.test_eq_sz("idx #18", indices.get().at(18), 426);
      result.test_eq_sz("idx #19", indices.get().at(19), 12);
      result.test_eq_sz("idx #20", indices.get().at(20), 324);
      result.test_eq_sz("idx #21", indices.get().at(21), 500);
      result.test_eq_sz("idx #22", indices.get().at(22), 234);
      result.test_eq_sz("idx #23", indices.get().at(23), 448);
      result.test_eq_sz("idx #24", indices.get().at(24), 200);
      result.test_eq_sz("idx #25", indices.get().at(25), 169);
      result.test_eq_sz("idx #26", indices.get().at(26), 490);
      result.test_eq_sz("idx #27", indices.get().at(27), 318);
      result.test_eq_sz("idx #28", indices.get().at(28), 319);
      result.test_eq_sz("idx #29", indices.get().at(29), 456);
      }

   return result;
   }

BOTAN_REGISTER_TEST("pubkey", "sphincsplus_fors", SPHINCS_Plus_FORS_Test);
BOTAN_REGISTER_TEST_FN("pubkey", "sphincsplus_fors_msg_to_index", test_fors_message_to_indices);

}  // namespace Botan_Tests

#endif  // BOTAN_HAS_SPHINCS_PLUS
