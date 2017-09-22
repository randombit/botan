/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include "test_rng.h"

#if defined(BOTAN_HAS_RSA)
   #include <botan/rsa.h>
   #include "test_pubkey.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_RSA)

class RSA_ES_KAT_Tests final : public PK_Encryption_Decryption_Test
   {
   public:
      RSA_ES_KAT_Tests()
         : PK_Encryption_Decryption_Test(
              "RSA",
              "pubkey/rsaes.vec",
              "E,P,Q,Msg,Ciphertext",
              "Padding,Nonce") {}

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const BigInt p = get_req_bn(vars, "P");
         const BigInt q = get_req_bn(vars, "Q");
         const BigInt e = get_req_bn(vars, "E");

         std::unique_ptr<Botan::Private_Key> key(new Botan::RSA_PrivateKey(p, q, e));
         return key;
         }
   };

class RSA_KEM_Tests final : public PK_KEM_Test
   {
   public:
      RSA_KEM_Tests()
         : PK_KEM_Test(
              "RSA",
              "pubkey/rsa_kem.vec",
              "E,P,Q,R,C0,KDF,OutLen,K") {}

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const BigInt p = get_req_bn(vars, "P");
         const BigInt q = get_req_bn(vars, "Q");
         const BigInt e = get_req_bn(vars, "E");

         std::unique_ptr<Botan::Private_Key> key(new Botan::RSA_PrivateKey(p, q, e));
         return key;
         }

   };

class RSA_Signature_KAT_Tests final : public PK_Signature_Generation_Test
   {
   public:
      RSA_Signature_KAT_Tests()
         : PK_Signature_Generation_Test(
              "RSA",
              "pubkey/rsa_sig.vec",
              "E,P,Q,Msg,Signature",
              "Padding,Nonce") {}

      std::string default_padding(const VarMap&) const override
         {
         return "Raw";
         }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const BigInt p = get_req_bn(vars, "P");
         const BigInt q = get_req_bn(vars, "Q");
         const BigInt e = get_req_bn(vars, "E");

         std::unique_ptr<Botan::Private_Key> key(new Botan::RSA_PrivateKey(p, q, e));
         return key;
         }
   };

class RSA_PSS_KAT_Tests final : public PK_Signature_Generation_Test
   {
   public:
      RSA_PSS_KAT_Tests()
         : PK_Signature_Generation_Test(
              "RSA",
              "pubkey/rsa_pss.vec",
              "P,Q,E,Hash,Nonce,Msg,Signature",
              "") {}

      std::string default_padding(const VarMap& var) const override
         {
         const std::string hash_name = get_req_str(var, "Hash");
         const size_t salt_size = get_req_bin(var, "Nonce").size();
         return "PSSR(" + hash_name + ",MGF1," + std::to_string(salt_size) + ")";
         }

      bool clear_between_callbacks() const override
         {
         return false;
         }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const BigInt p = get_req_bn(vars, "P");
         const BigInt q = get_req_bn(vars, "Q");
         const BigInt e = get_req_bn(vars, "E");

         std::unique_ptr<Botan::Private_Key> key(new Botan::RSA_PrivateKey(p, q, e));
         return key;
         }
   };

class RSA_PSS_Raw_KAT_Tests final : public PK_Signature_Generation_Test
   {
   public:
      RSA_PSS_Raw_KAT_Tests()
         : PK_Signature_Generation_Test(
              "RSA",
              "pubkey/rsa_pss_raw.vec",
              "P,Q,E,Hash,Nonce,Msg,Signature",
              "") {}

      std::string default_padding(const VarMap& var) const override
         {
         const std::string hash_name = get_req_str(var, "Hash");
         const size_t salt_size = get_req_bin(var, "Nonce").size();
         return "PSSR_Raw(" + hash_name + ",MGF1," + std::to_string(salt_size) + ")";
         }

      bool clear_between_callbacks() const override
         {
         return false;
         }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const BigInt p = get_req_bn(vars, "P");
         const BigInt q = get_req_bn(vars, "Q");
         const BigInt e = get_req_bn(vars, "E");

         std::unique_ptr<Botan::Private_Key> key(new Botan::RSA_PrivateKey(p, q, e));
         return key;
         }
   };

class RSA_Signature_Verify_Tests final : public PK_Signature_Verification_Test
   {
   public:
      RSA_Signature_Verify_Tests()
         : PK_Signature_Verification_Test(
              "RSA",
              "pubkey/rsa_verify.vec",
              "E,N,Msg,Signature",
              "Padding")  {}

      std::string default_padding(const VarMap&) const override
         {
         return "Raw";
         }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override
         {
         const BigInt n = get_req_bn(vars, "N");
         const BigInt e = get_req_bn(vars, "E");

         std::unique_ptr<Botan::Public_Key> key(new Botan::RSA_PublicKey(n, e));
         return key;
         }
   };

class RSA_Signature_Verify_Invalid_Tests final : public PK_Signature_NonVerification_Test
   {
   public:
      RSA_Signature_Verify_Invalid_Tests()
         : PK_Signature_NonVerification_Test(
              "RSA",
              "pubkey/rsa_invalid.vec",
              "Padding,E,N,Msg,InvalidSignature") {}

      std::string default_padding(const VarMap&) const override
         {
         return "Raw";
         }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override
         {
         const BigInt n = get_req_bn(vars, "N");
         const BigInt e = get_req_bn(vars, "E");
         std::unique_ptr<Botan::Public_Key> key(new Botan::RSA_PublicKey(n, e));
         return key;
         }
   };

class RSA_Keygen_Tests final : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override
         {
         return { "1024", "1280" };
         }
      std::string algo_name() const override
         {
         return "RSA";
         }
   };

class RSA_Blinding_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("RSA blinding");

#if defined(BOTAN_HAS_EMSA_RAW) || defined(BOTAN_HAS_EME_RAW)
         Botan::RSA_PrivateKey rsa(Test::rng(), 1024);
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

         Botan::PK_Signer signer(rsa, Test::rng(), "Raw", Botan::IEEE_1363, "base"); // don't try this at home
         Botan::PK_Verifier verifier(rsa, "Raw");

         for(size_t i = 1; i <= BOTAN_BLINDING_REINIT_INTERVAL * 6; ++i)
            {
            std::vector<uint8_t> input(16);
            input[input.size() - 1] = static_cast<uint8_t>(i);

            signer.update(input);

            // assert RNG is not called in this situation
            std::vector<uint8_t> signature = signer.signature(null_rng);

            result.test_eq("Signature verifies",
                           verifier.verify_message(input, signature), true);
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

         Botan::PK_Encryptor_EME encryptor(rsa, Test::rng(), "Raw");   // don't try this at home

         // test blinding reinit interval
         // Seed Fixed_Output_RNG only with enough bytes for the initial blinder initialization
         Botan_Tests::Fixed_Output_RNG fixed_rng(Botan::unlock(Test::rng().random_vec(rsa.get_n().bytes())));
         Botan::PK_Decryptor_EME decryptor(rsa, fixed_rng, "Raw", "base");

         for(size_t i = 1; i <= BOTAN_BLINDING_REINIT_INTERVAL ; ++i)
            {
            std::vector<uint8_t> input(16);
            input[ input.size() - 1 ] = static_cast<uint8_t>(i);

            std::vector<uint8_t> ciphertext = encryptor.encrypt(input, null_rng);

            std::vector<uint8_t> plaintext = Botan::unlock(decryptor.decrypt(ciphertext));
            plaintext.insert(plaintext.begin(), input.size() - 1, 0);

            result.test_eq("Successful decryption", plaintext, input);
            }

         result.test_eq("RNG is no longer seeded", fixed_rng.is_seeded(), false);

         // one more decryption should trigger a blinder reinitialization
         result.test_throws("RSA blinding reinit",
                            "Test error Fixed output RNG ran out of bytes, test bug?",
                            [&decryptor, &encryptor, &null_rng]()
            {
            std::vector<uint8_t> ciphertext = encryptor.encrypt(std::vector<uint8_t>(16, 5), null_rng);
            decryptor.decrypt(ciphertext);
            });

#endif

         return std::vector<Test::Result> {result};
         }
   };

BOTAN_REGISTER_TEST("rsa_encrypt", RSA_ES_KAT_Tests);
BOTAN_REGISTER_TEST("rsa_sign", RSA_Signature_KAT_Tests);
BOTAN_REGISTER_TEST("rsa_pss", RSA_PSS_KAT_Tests);
BOTAN_REGISTER_TEST("rsa_pss_raw", RSA_PSS_Raw_KAT_Tests);
BOTAN_REGISTER_TEST("rsa_verify", RSA_Signature_Verify_Tests);
BOTAN_REGISTER_TEST("rsa_verify_invalid", RSA_Signature_Verify_Invalid_Tests);
BOTAN_REGISTER_TEST("rsa_kem", RSA_KEM_Tests);
BOTAN_REGISTER_TEST("rsa_keygen", RSA_Keygen_Tests);
BOTAN_REGISTER_TEST("rsa_blinding", RSA_Blinding_Tests);

#endif

}

}
