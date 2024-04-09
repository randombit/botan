/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_rng.h"
#include "tests.h"

#if defined(BOTAN_HAS_RSA)
   #include "test_pubkey.h"
   #include <botan/rsa.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_RSA)

std::unique_ptr<Botan::Private_Key> load_rsa_private_key(const VarMap& vars) {
   const BigInt p = vars.get_req_bn("P");
   const BigInt q = vars.get_req_bn("Q");
   const BigInt e = vars.get_req_bn("E");

   return std::make_unique<Botan::RSA_PrivateKey>(p, q, e);
}

std::unique_ptr<Botan::Public_Key> load_rsa_public_key(const VarMap& vars) {
   const BigInt n = vars.get_req_bn("N");
   const BigInt e = vars.get_req_bn("E");

   return std::make_unique<Botan::RSA_PublicKey>(n, e);
}

class RSA_ES_KAT_Tests final : public PK_Encryption_Decryption_Test {
   public:
      RSA_ES_KAT_Tests() : PK_Encryption_Decryption_Test("RSA", "pubkey/rsaes.vec", "E,P,Q,Msg,Ciphertext", "Nonce") {}

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         return load_rsa_private_key(vars);
      }
};

class RSA_Decryption_KAT_Tests final : public PK_Decryption_Test {
   public:
      RSA_Decryption_KAT_Tests() : PK_Decryption_Test("RSA", "pubkey/rsa_decrypt.vec", "E,P,Q,Ciphertext,Msg") {}

      bool clear_between_callbacks() const override { return false; }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         return load_rsa_private_key(vars);
      }
};

class RSA_KEM_Tests final : public PK_KEM_Test {
   public:
      RSA_KEM_Tests() : PK_KEM_Test("RSA", "pubkey/rsa_kem.vec", "E,P,Q,R,C0,KDF,K") {}

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         return load_rsa_private_key(vars);
      }
};

class RSA_Signature_KAT_Tests final : public PK_Signature_Generation_Test {
   public:
      RSA_Signature_KAT_Tests() :
            PK_Signature_Generation_Test("RSA", "pubkey/rsa_sig.vec", "E,P,Q,Msg,Signature", "Nonce") {}

      std::string default_padding(const VarMap& /*unused*/) const override { return "Raw"; }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         return load_rsa_private_key(vars);
      }
};

class RSA_PSS_KAT_Tests final : public PK_Signature_Generation_Test {
   public:
      RSA_PSS_KAT_Tests() :
            PK_Signature_Generation_Test("RSA", "pubkey/rsa_pss.vec", "P,Q,E,Hash,Nonce,Msg,Signature", "") {}

      std::string default_padding(const VarMap& vars) const override {
         const std::string hash_name = vars.get_req_str("Hash");
         const size_t salt_size = vars.get_req_bin("Nonce").size();
         return "PSSR(" + hash_name + ",MGF1," + std::to_string(salt_size) + ")";
      }

      bool clear_between_callbacks() const override { return false; }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         return load_rsa_private_key(vars);
      }
};

class RSA_PSS_Raw_KAT_Tests final : public PK_Signature_Generation_Test {
   public:
      RSA_PSS_Raw_KAT_Tests() :
            PK_Signature_Generation_Test("RSA", "pubkey/rsa_pss_raw.vec", "P,Q,E,Hash,Nonce,Msg,Signature", "") {}

      std::string default_padding(const VarMap& vars) const override {
         const std::string hash_name = vars.get_req_str("Hash");
         const size_t salt_size = vars.get_req_bin("Nonce").size();
         return "PSSR_Raw(" + hash_name + ",MGF1," + std::to_string(salt_size) + ")";
      }

      bool clear_between_callbacks() const override { return false; }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         return load_rsa_private_key(vars);
      }
};

class RSA_Signature_Verify_Tests final : public PK_Signature_Verification_Test {
   public:
      RSA_Signature_Verify_Tests() :
            PK_Signature_Verification_Test("RSA", "pubkey/rsa_verify.vec", "E,N,Msg,Signature") {}

      std::string default_padding(const VarMap& /*unused*/) const override { return "Raw"; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         return load_rsa_public_key(vars);
      }
};

class RSA_Signature_Verify_Invalid_Tests final : public PK_Signature_NonVerification_Test {
   public:
      RSA_Signature_Verify_Invalid_Tests() :
            PK_Signature_NonVerification_Test("RSA", "pubkey/rsa_invalid.vec", "E,N,Msg,InvalidSignature") {}

      std::string default_padding(const VarMap& /*unused*/) const override { return "Raw"; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         return load_rsa_public_key(vars);
      }
};

class RSA_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override { return {"1024", "1280"}; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view /* keygen_params */,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> /* raw_pk */) const override {
         // RSA does not implement raw public key encoding
         return nullptr;
      }

      std::string algo_name() const override { return "RSA"; }
};

class RSA_Keygen_Stability_Tests final : public PK_Key_Generation_Stability_Test {
   public:
      RSA_Keygen_Stability_Tests() : PK_Key_Generation_Stability_Test("RSA", "pubkey/rsa_keygen.vec") {}
};

class RSA_Keygen_Bad_RNG_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("RSA keygen with bad RNG");

         /*
         We don't need to count requests here; actually this test
         is relying on the fact that the Request_Counting_RNG outputs
         repeating 808080...
         */
         Request_Counting_RNG rng;

         try {
            Botan::RSA_PrivateKey rsa(rng, 1024);
            result.test_failure("Generated a key with a bad RNG");
         } catch(Botan::Internal_Error& e) {
            result.test_success("Key generation with bad RNG failed");
            result.test_eq("Expected message", e.what(), "Internal error: RNG failure during RSA key generation");
         }

         return {result};
      }
};

class RSA_Blinding_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("RSA blinding");

         /* This test makes only sense with the base provider, else skip it. */
         if(provider_filter({"base"}).empty()) {
            result.note_missing("base provider");
            return std::vector<Test::Result>{result};
         }

   #if defined(BOTAN_HAS_EMSA_RAW) || defined(BOTAN_HAS_EME_RAW)
         Botan::RSA_PrivateKey rsa(this->rng(), 1024);
         Botan::Null_RNG null_rng;
   #endif

   #if defined(BOTAN_HAS_EMSA_RAW)

         /*
         * The blinder chooses a new starting point BOTAN_BLINDING_REINIT_INTERVAL
         * so sign several times that with a single key.
         *
         * Very small values (padding/hashing disabled, only low byte set on input)
         * are used as an additional test on the blinders.
         */

         Botan::PK_Signer signer(
            rsa, this->rng(), "Raw", Botan::Signature_Format::Standard, "base");  // don't try this at home
         Botan::PK_Verifier verifier(rsa, "Raw", Botan::Signature_Format::Standard, "base");

         for(size_t i = 1; i <= BOTAN_BLINDING_REINIT_INTERVAL * 6; ++i) {
            std::vector<uint8_t> input(16);
            input[input.size() - 1] = static_cast<uint8_t>(i | 1);

            signer.update(input);

            // assert RNG is not called in this situation
            std::vector<uint8_t> signature = signer.signature(null_rng);

            result.test_eq("Signature verifies", verifier.verify_message(input, signature), true);
         }
   #endif

   #if defined(BOTAN_HAS_EME_RAW)

         /*
         * The blinder chooses a new starting point BOTAN_BLINDING_REINIT_INTERVAL
         * so decrypt several times that with a single key.
         *
         * Very small values (padding/hashing disabled, only low byte set on input)
         * are used as an additional test on the blinders.
         */

         Botan::PK_Encryptor_EME encryptor(rsa, this->rng(), "Raw", "base");  // don't try this at home

         /*
         Test blinding reinit interval

         Seed Fixed_Output_RNG only with enough bytes for the initial
         blinder initialization plus the exponent blinding bits which
         is 2*64 bits per operation.
         */
         const size_t rng_bytes = rsa.get_n().bytes() + (2 * 8 * BOTAN_BLINDING_REINIT_INTERVAL);

         Botan_Tests::Fixed_Output_RNG fixed_rng(this->rng(), rng_bytes);
         Botan::PK_Decryptor_EME decryptor(rsa, fixed_rng, "Raw", "base");

         for(size_t i = 1; i <= BOTAN_BLINDING_REINIT_INTERVAL; ++i) {
            std::vector<uint8_t> input(16);
            input[input.size() - 1] = static_cast<uint8_t>(i);

            std::vector<uint8_t> ciphertext = encryptor.encrypt(input, null_rng);

            std::vector<uint8_t> plaintext = Botan::unlock(decryptor.decrypt(ciphertext));
            plaintext.insert(plaintext.begin(), input.size() - 1, 0);

            result.test_eq("Successful decryption", plaintext, input);
         }

         result.test_eq("RNG is no longer seeded", fixed_rng.is_seeded(), false);

         // one more decryption should trigger a blinder reinitialization
         result.test_throws("RSA blinding reinit",
                            "Test error Fixed output RNG ran out of bytes, test bug?",
                            [&decryptor, &encryptor, &null_rng]() {
                               std::vector<uint8_t> ciphertext =
                                  encryptor.encrypt(std::vector<uint8_t>(16, 5), null_rng);
                               decryptor.decrypt(ciphertext);
                            });

   #endif

         return std::vector<Test::Result>{result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "rsa_encrypt", RSA_ES_KAT_Tests);
BOTAN_REGISTER_TEST("pubkey", "rsa_decrypt", RSA_Decryption_KAT_Tests);
BOTAN_REGISTER_TEST("pubkey", "rsa_sign", RSA_Signature_KAT_Tests);
BOTAN_REGISTER_TEST("pubkey", "rsa_pss", RSA_PSS_KAT_Tests);
BOTAN_REGISTER_TEST("pubkey", "rsa_pss_raw", RSA_PSS_Raw_KAT_Tests);
BOTAN_REGISTER_TEST("pubkey", "rsa_verify", RSA_Signature_Verify_Tests);
BOTAN_REGISTER_TEST("pubkey", "rsa_verify_invalid", RSA_Signature_Verify_Invalid_Tests);
BOTAN_REGISTER_TEST("pubkey", "rsa_kem", RSA_KEM_Tests);
BOTAN_REGISTER_TEST("pubkey", "rsa_keygen", RSA_Keygen_Tests);
BOTAN_REGISTER_TEST("pubkey", "rsa_keygen_stability", RSA_Keygen_Stability_Tests);
BOTAN_REGISTER_TEST("pubkey", "rsa_keygen_badrng", RSA_Keygen_Bad_RNG_Test);
BOTAN_REGISTER_TEST("pubkey", "rsa_blinding", RSA_Blinding_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
