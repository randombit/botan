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
#include <botan/internal/sp_hash.h>
#include <botan/sp_parameters.h>
#include <botan/sphincsplus.h>
#include <botan/secmem.h>


namespace Botan_Tests {

class SPHINCS_Plus_Test final : public Text_Based_Test
   {
   private:
      /// @returns (secret_seed, sk_prf, public_seed, sphincs_root)
      std::tuple<Botan::secure_vector<uint8_t>, Botan::secure_vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>>
      parse_sk(std::vector<uint8_t> sk, Botan::Sphincs_Parameters& params)
         {
         BOTAN_ASSERT_NOMSG(sk.size() == 4 * params.n());
         Botan::secure_vector<uint8_t> secret_seed(sk.begin(), sk.begin() + params.n());
         Botan::secure_vector<uint8_t> sk_prf(sk.begin() + params.n(), sk.begin() + 2*params.n());
         std::vector<uint8_t> public_seed(sk.begin() + 2*params.n(), sk.begin() + 3*params.n());
         std::vector<uint8_t> sphincs_root(sk.begin() + 3*params.n(), sk.end());

         return std::make_tuple(secret_seed, sk_prf, public_seed, sphincs_root);
         }

      std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
      parse_signature_with_message(std::vector<uint8_t> sig_with_msg, size_t msg_size, Botan::Sphincs_Parameters& params)
         {
         BOTAN_ASSERT_NOMSG(sig_with_msg.size() == params.sphincs_signature_bytes() + msg_size);
         std::vector<uint8_t> signature(sig_with_msg.begin(), sig_with_msg.begin() + params.sphincs_signature_bytes());
         std::vector<uint8_t> message(sig_with_msg.begin() + params.sphincs_signature_bytes(), sig_with_msg.end());

         return std::make_pair(signature, message);
         }

   public:
      SPHINCS_Plus_Test()
         : Text_Based_Test("pubkey/sphincsplus.vec", "SphincsParameterSet,sk,Msg,OptRand,Signature")
      {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) final
         {
         Test::Result result("SPHINCS+ ");

         auto params = Botan::Sphincs_Parameters::create(vars.get_req_str("SphincsParameterSet"));
         auto hashes = Botan::Sphincs_Hash_Functions::create(params);

         auto [secret_seed, sk_prf, public_seed, root_ref] = parse_sk(vars.get_req_bin("sk"), params);

         const std::vector<uint8_t> msg = vars.get_req_bin("Msg");

         const std::vector<uint8_t> sig_ref = vars.get_req_bin("Signature");
         const std::vector<uint8_t> opt_rand = vars.get_req_bin("OptRand");

         auto sig = Botan::sphincsplus_sign(msg,
                                            secret_seed,
                                            sk_prf,
                                            public_seed,
                                            opt_rand,
                                            root_ref,
                                            params);
         result.test_is_eq("signature creation", sig, sig_ref);

         auto [sig_raw, msg_from_sig] = parse_signature_with_message(sig_ref, msg.size(), params);
         bool verify_result = Botan::sphincsplus_verify(msg, sig_raw, public_seed, root_ref, params);
         result.test_is_eq("verification of a vaild signature", verify_result, true);

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
