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

#include "botan/mldsa_comp_parameters.h"
#include "tests.h"

#include <format>
#include <iostream>  // TODO remove
#include <memory>
#include <string_view>
#if defined(BOTAN_HAS_MLDSA_COMPOSITE)

   #include <botan/base64.h>
   #include <botan/exceptn.h>
   #include <botan/hash.h>
   #include <botan/hex.h>
   #include <botan/mldsa_comp.h>
   #include <botan/pk_algs.h>
   #include <botan/pk_keys.h>
   #include <botan/pkcs8.h>
   #include <botan/pubkey.h>
   #include <botan/rng.h>
   #include <botan/secmem.h>

   #include "test_pubkey.h"
   #include "test_rng.h"
// TODO: SPLIT OUT TESTS THAT DON'T REQUIRE FILESYSTEM
   #if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
      #include <botan/pkix_enums.h>
      #include <botan/x509cert.h>
   #endif

#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_MLDSA_COMPOSITE)

namespace {

std::vector<uint8_t> decode_var_base64(const VarMap& vars, std::string_view var) {
   const auto var_b64 = vars.get_req_str(var);
   const auto var_sv = Botan::base64_decode(var_b64);
   return std::vector<uint8_t>(var_sv.begin(), var_sv.end());
}

void sign_and_verify(const Botan::Private_Key& priv_key,
                     const Botan::Public_Key& pub_key,
                     Botan::RandomNumberGenerator& rng,
                     Test::Result& test_result,
                     std::string_view test_context) {
   const char* message = "The quick brown fox jumps over the lazy dog.";
   Botan::PK_Signer signer(priv_key, rng, "");
   signer.update(message);
   std::vector<uint8_t> signature2 = signer.signature(rng);

   Botan::PK_Verifier verifier2(pub_key, "");
   verifier2.update(message);
   test_result.test_bool_eq(
      std::format("verification of correct signature ({})", test_context), verifier2.check_signature(signature2), true);
}
}  // namespace

//
//

class MLDSA_Composite_RT_Tests : public Test {
   public:
      static Test::Result run_roundtrip(Botan::MLDSA_Composite_Param::id_t id) {
         auto param = Botan::MLDSA_Composite_Param::from_id_or_throw(id);
         std::string test_name = std::string("MLDSA_Composite_round_trip_") + param.id_str;
         Test::Result result(test_name);
         auto rng = Test::new_rng(test_name);

         auto priv_key_generated(Botan::create_private_key(param.id_str, *rng));
         if(nullptr == priv_key_generated) {
            result.test_bool_eq("generated private key non-null", false, true);
         } else {
            //std::cout << "retrieving public key from generated private key\n";
            auto pub_key_generated = priv_key_generated->public_key();
            if(nullptr == pub_key_generated) {
               result.test_bool_eq("generated pub key key non-null", false, true);
            } else {
               //std::cout << "calling sign_and_verify() with generated key pair\n";
               sign_and_verify(*priv_key_generated, *pub_key_generated, *rng, result, "produced with generated key");
            }
         }
         Botan::secure_vector<uint8_t> private_enc = priv_key_generated->private_key_bits();
         std::vector<uint8_t> public_enc = priv_key_generated->public_key_bits();
         const Botan::MLDSA_Composite_PrivateKey priv_key_redec(priv_key_generated->algorithm_identifier(),
                                                                private_enc);
         const Botan::MLDSA_Composite_PublicKey pub_key_redec(priv_key_generated->algorithm_identifier(), public_enc);
         sign_and_verify(priv_key_redec, pub_key_redec, *rng, result, "produced with re-decoded key");
         return result;
      }

      std::vector<Test::Result> run() override {
         return {
            run_roundtrip(Botan::MLDSA_Composite_Param::id_t::id_MLDSA44_RSA2048_PKCS15_SHA256),
            run_roundtrip(Botan::MLDSA_Composite_Param::id_t::id_MLDSA44_RSA2048_PSS_SHA256),
            // TODO: ADD INVALID SIGNATURE AND KEY SIZE TESTS
         };
      }
};

BOTAN_REGISTER_TEST("pubkey", "mldsa_composite_roundtrips", MLDSA_Composite_RT_Tests);

   #if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

class MLDSA_Composite_KAT_Tests : public Text_Based_Test {
   public:
      MLDSA_Composite_KAT_Tests() :
            Text_Based_Test("pubkey/mldsa_composite.vec", "tcId,pk,x5c,sk,sk_pkcs8,s,sWithContext") {}

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
         //std::cout << "test name = " << name << std::endl;
         auto tcId = vars.get_req_str("tcId");
         if(tcId.starts_with("id-")) {
            tcId = tcId.substr(3);
         }
         //std::cout << "tcId = " << tcId << std::endl;
         const auto pk = vars.get_req_str("pk");
         const auto pk_bin = Botan::base64_decode(pk);

         const auto sk = vars.get_req_str("sk");
         const auto sk_bin = Botan::base64_decode(sk);

         const auto sig_bin = Botan::base64_decode(vars.get_req_str("s"));

         const auto comp_parm = Botan::MLDSA_Composite_Param::from_id_str_or_throw(tcId);

         const char* message = "The quick brown fox jumps over the lazy dog.";
         std::unique_ptr<Botan::Public_Key> pubkey;
         std::unique_ptr<Botan::Private_Key> privkey;
         try {
            pubkey = std::make_unique<Botan::MLDSA_Composite_PublicKey>(comp_parm.id, pk_bin);
         } catch(const Botan::Exception& e) {
            exc_during_pubkey_decoding = true;
         }
         //std::cout << "pubkey decoding passed\n";
         result.test_bool_eq("pubkey decoding OK", !exc_during_pubkey_decoding, pubkey_valid);
         if(exc_during_pubkey_decoding) {
            return result;
         }
         Botan::PK_Verifier verifier(*pubkey, "");
         verifier.update(message);
         result.test_bool_eq("verification of correct signature", verifier.check_signature(sig_bin), true);
         //std::cout << "\nis " << (verifier.check_signature(sig_bin) ? "valid" : "invalid");
         //std::cout << "verification passed \n";

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
         sign_and_verify(*privkey, *pubkey, *rng, result, "produced by decoded private key");
         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "mldsa_composite_kat", MLDSA_Composite_KAT_Tests);

      #if defined(BOTAN_HAS_X509_CERTIFICATES)

class MLDSA_Composite_X509_Tests : public Text_Based_Test {
   public:
      MLDSA_Composite_X509_Tests() :
            Text_Based_Test("pubkey/mldsa_composite.vec", "tcId,x5c,sk_pkcs8", "pk,sk,s,sWithContext") {}

      Test::Result run_one_test(const std::string& name, const VarMap& vars) override {
         auto rng = std::make_unique<CTR_DRBG_AES256>(Botan::hex_decode(
            "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"));
         Test::Result result(name);

         std::vector<uint8_t> x5c = decode_var_base64(vars, "x5c");
         const Botan::X509_Certificate cert(x5c);
         Test::Result this_result(name);
         auto ver_res = cert.verify_signature(*cert.subject_public_key());
         result.test_is_true("signature of certificate verifies", ver_res.first == Botan::Certificate_Status_Code::OK);

         const std::shared_ptr<Botan::Private_Key> private_key =
            Botan::PKCS8::load_key(decode_var_base64(vars, "sk_pkcs8"));

         sign_and_verify(*private_key,
                         *cert.subject_public_key(),
                         *rng,
                         result,
                         "PKCS#8 private key signs and cert's public key verifies");
         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "mldsa_composite_x509", MLDSA_Composite_X509_Tests);
      #endif
   #endif
#endif
}  // namespace Botan_Tests
