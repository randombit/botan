/*
 * Tests for Crystals Dilithium
 * - KAT tests using the KAT vectors from
 *   https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/Dilithium-Round3.zip
 *
 * (C) 2022,2023 Jack Lloyd
 * (C) 2022 Manuel Glaser, Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "botan/exceptn.h"
#include "botan/hex.h"
#include "botan/pk_keys.h"
#include "tests.h"

#include <iostream>  // TODO remove
#include <memory>
#if defined(BOTAN_HAS_MLDSA_COMPOSITE)
   #include <botan/base64.h>
   #include <botan/hash.h>
   #include <botan/mldsa_comp.h>
   #include <botan/pk_algs.h>
   #include <botan/pubkey.h>

   #include "test_pubkey.h"
   #include "test_rng.h"

#endif

namespace Botan_Tests {
#if defined(BOTAN_HAS_MLDSA_COMPOSITE)

class MLDSA_Composite_KAT_Tests : public Text_Based_Test {
   public:
      // NOLINTNEXTLINE(*crtp-constructor-accessibility)
      MLDSA_Composite_KAT_Tests() :
            Text_Based_Test("pubkey/mldsa_composite.vec", "tcId,pk,x5c,sk,sk_pkcs8,s,sWithContext") {}

      // TODO: NEGATIVE TESTS WITH TOO SHORT PUBLIC AND PRIVATE KEYS
      Test::Result run_one_test(const std::string& name, const VarMap& vars) override {
         auto rng = std::make_unique<CTR_DRBG_AES256>(Botan::hex_decode(
            "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"));
         bool pubkey_valid = true;
         bool privkey_valid = true;
         bool exc_during_pubkey_decoding = false;
         bool exc_during_privkey_decoding = false;
         if(name.ends_with("pubkey-invalid")) {
            pubkey_valid = false;
         }
         if(name.ends_with("privkey-invalid")) {
            privkey_valid = false;
         }
         Test::Result result(name);
         std::cout << "test name = " << name << std::endl;
         auto tcId = vars.get_req_str("tcId");
         if(tcId.starts_with("id-")) {
            tcId = tcId.substr(3);
         }
         std::cout << "tcId = " << tcId << std::endl;
         const auto pk = vars.get_req_str("pk");
         const auto pk_bin = Botan::base64_decode(pk);

         const auto sk = vars.get_req_str("sk");
         const auto sk_bin = Botan::base64_decode(sk);

         const auto sig_bin = Botan::base64_decode(vars.get_req_str("s"));

         const auto comp_parm = Botan::MLDSA_Composite_Param::get_param_by_id_str(tcId);

         const char* message = "The quick brown fox jumps over the lazy dog.";
         std::unique_ptr<Botan::Public_Key> pubkey;
         std::unique_ptr<Botan::Private_Key> privkey;
         try {
            pubkey = std::make_unique<Botan::MLDSA_Composite_PublicKey>(comp_parm.id, pk_bin);
         } catch(const Botan::Exception& e) {
            exc_during_pubkey_decoding = true;
         }
         std::cout << "pubkey decoding passed\n";
         result.test_bool_eq("pubkey decoding OK", !exc_during_pubkey_decoding, pubkey_valid);
         if(exc_during_pubkey_decoding) {
            return result;
         }
         Botan::PK_Verifier verifier(*pubkey, "");
         verifier.update(message);
         result.test_bool_eq("verification of correct signature", verifier.check_signature(sig_bin), true);
         //std::cout << "\nis " << (verifier.check_signature(sig_bin) ? "valid" : "invalid");
         std::cout << "verification passed \n";

         try {
            privkey = std::make_unique<Botan::MLDSA_Composite_PrivateKey>(comp_parm.id, sk_bin);
         } catch(const Botan::Exception& e) {
            exc_during_privkey_decoding = true;
         }
         result.test_bool_eq("privkey decoding OK", !exc_during_privkey_decoding, privkey_valid);
         if(exc_during_privkey_decoding) {
            return result;
         }
         // sign data
         std::cout << "signing data with decoded private key\n";
         Botan::PK_Signer signer(*privkey, *rng, "");
         signer.update(message);
         std::vector<uint8_t> signature2 = signer.signature(*rng);
         std::cout << "finished signing data with decoded private key\n";
         //std::cout << "Signature:\n" << Botan::hex_encode(signature);

         Botan::PK_Verifier verifier2(*pubkey, "");
         verifier2.update(message);
         result.test_bool_eq("verification of correct signature (produced by decoded private key)",
                             verifier2.check_signature(signature2),
                             true);
         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "mldsa_composite_kat", MLDSA_Composite_KAT_Tests);

#endif
}  // namespace Botan_Tests
