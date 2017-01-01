/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
  #include "test_pubkey.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_RSA)

class RSA_ES_KAT_Tests : public PK_Encryption_Decryption_Test
   {
   public:
      RSA_ES_KAT_Tests() : PK_Encryption_Decryption_Test(
         "RSA",
         "pubkey/rsaes.vec",
         "E,P,Q,Msg,Ciphertext",
         "Padding,Nonce")
         {}

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const BigInt p = get_req_bn(vars, "P");
         const BigInt q = get_req_bn(vars, "Q");
         const BigInt e = get_req_bn(vars, "E");

         std::unique_ptr<Botan::Private_Key> key(new Botan::RSA_PrivateKey(p, q, e));
         return key;
         }
   };

class RSA_KEM_Tests : public PK_KEM_Test
   {
   public:
      RSA_KEM_Tests() : PK_KEM_Test(
         "RSA",
         "pubkey/rsa_kem.vec",
         "E,P,Q,R,C0,KDF,OutLen,K")
         {}

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const BigInt p = get_req_bn(vars, "P");
         const BigInt q = get_req_bn(vars, "Q");
         const BigInt e = get_req_bn(vars, "E");

         std::unique_ptr<Botan::Private_Key> key(new Botan::RSA_PrivateKey(p, q, e));
         return key;
         }

   };

class RSA_Signature_KAT_Tests : public PK_Signature_Generation_Test
   {
   public:
      RSA_Signature_KAT_Tests() : PK_Signature_Generation_Test(
         "RSA",
         "pubkey/rsa_sig.vec",
         "E,P,Q,Msg,Signature",
         "Padding,Nonce")
         {}

      std::string default_padding(const VarMap&) const override { return "Raw"; }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const BigInt p = get_req_bn(vars, "P");
         const BigInt q = get_req_bn(vars, "Q");
         const BigInt e = get_req_bn(vars, "E");

         std::unique_ptr<Botan::Private_Key> key(new Botan::RSA_PrivateKey(p, q, e));
         return key;
         }
   };

class RSA_Signature_Verify_Tests : public PK_Signature_Verification_Test
   {
   public:
      RSA_Signature_Verify_Tests() : PK_Signature_Verification_Test(
         "RSA",
         "pubkey/rsa_verify.vec",
         "E,N,Msg,Signature",
         "Padding")
         {}

      std::string default_padding(const VarMap&) const override { return "Raw"; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override
         {
         const BigInt n = get_req_bn(vars, "N");
         const BigInt e = get_req_bn(vars, "E");

         std::unique_ptr<Botan::Public_Key> key(new Botan::RSA_PublicKey(n, e));
         return key;
         }
   };

class RSA_Signature_Verify_Invalid_Tests : public PK_Signature_NonVerification_Test
   {
   public:
      RSA_Signature_Verify_Invalid_Tests() : PK_Signature_NonVerification_Test(
         "RSA",
         "pubkey/rsa_invalid.vec",
         "Padding,E,N,Msg,InvalidSignature")
         {}

      std::string default_padding(const VarMap&) const override { return "Raw"; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override
         {
         const BigInt n = get_req_bn(vars, "N");
         const BigInt e = get_req_bn(vars, "E");
         std::unique_ptr<Botan::Public_Key> key(new Botan::RSA_PublicKey(n, e));
         return key;
         }
   };

class RSA_Keygen_Tests : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override { return { "1024", "1280" }; }
      std::string algo_name() const override { return "RSA"; }
   };

class RSA_Blinding_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("RSA blinding");

#if defined(BOTAN_HAS_EME_RAW)

         /*
         * The blinder chooses a new starting point BOTAN_BLINDING_REINIT_INTERVAL
         * so sign several times that with a single key.
         *
         * Very small values (padding/hashing disabled, only low byte set on input)
         * are used as an additional test on the blinders.
         */

         Botan::RSA_PrivateKey rsa(Test::rng(), 1024);

         Botan::PK_Signer signer(rsa, Test::rng(), "Raw"); // don't try this at home
         Botan::PK_Verifier verifier(rsa, "Raw");

         Botan::Null_RNG null_rng;
         for(size_t i = 1; i <= BOTAN_BLINDING_REINIT_INTERVAL * 6; ++i)
            {
            std::vector<uint8_t> input(16);
            input[input.size()-1] = static_cast<uint8_t>(i);

            signer.update(input);

            // assert RNG is not called in this situation
            std::vector<uint8_t> signature = signer.signature(null_rng);

            result.test_eq("Signature verifies",
                           verifier.verify_message(input, signature), true);
            }
#endif

         return std::vector<Test::Result>{result};
         }
   };

BOTAN_REGISTER_TEST("rsa_encrypt", RSA_ES_KAT_Tests);
BOTAN_REGISTER_TEST("rsa_sign", RSA_Signature_KAT_Tests);
BOTAN_REGISTER_TEST("rsa_verify", RSA_Signature_Verify_Tests);
BOTAN_REGISTER_TEST("rsa_verify_invalid", RSA_Signature_Verify_Invalid_Tests);
BOTAN_REGISTER_TEST("rsa_kem", RSA_KEM_Tests);
BOTAN_REGISTER_TEST("rsa_keygen", RSA_Keygen_Tests);
BOTAN_REGISTER_TEST("rsa_blinding", RSA_Blinding_Tests);

#endif

}

}
