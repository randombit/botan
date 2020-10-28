/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_CURVE_25519)
   #include "test_pubkey.h"
   #include <botan/curve25519.h>
   #include <botan/x509_key.h>
   #include <botan/pkcs8.h>
   #include <botan/data_src.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_CURVE_25519)

class Curve25519_Sclarmult_Tests final : public Text_Based_Test
   {
   public:
      Curve25519_Sclarmult_Tests() : Text_Based_Test(
            "pubkey/c25519_scalar.vec",
            "Secret,Basepoint,Out") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         const std::vector<uint8_t> secret    = vars.get_req_bin("Secret");
         const std::vector<uint8_t> basepoint = vars.get_req_bin("Basepoint");
         const std::vector<uint8_t> expected  = vars.get_req_bin("Out");

         std::vector<uint8_t> got(32);
         Botan::curve25519_donna(got.data(), secret.data(), basepoint.data());

         Test::Result result("Curve25519 scalarmult");
         result.test_eq("basemult", got, expected);
         return result;
         }
   };
BOTAN_REGISTER_TEST("pubkey", "curve25519_scalar", Curve25519_Sclarmult_Tests);

class Curve25519_Agreement_Tests final : public PK_Key_Agreement_Test
   {
   public:
      Curve25519_Agreement_Tests() : PK_Key_Agreement_Test(
         "X25519",
         "pubkey/x25519.vec",
         "Secret,CounterKey,K") {}

      std::string default_kdf(const VarMap&) const override
         {
         return "Raw";
         }

      std::unique_ptr<Botan::Private_Key> load_our_key(const std::string&,
                                                       const VarMap& vars) override
         {
         const std::vector<uint8_t> secret_vec = vars.get_req_bin("Secret");
         Botan::secure_vector<uint8_t> secret(secret_vec.begin(), secret_vec.end());
         return std::unique_ptr<Botan::Private_Key>(new Botan::Curve25519_PrivateKey(secret));
         }

      std::vector<uint8_t> load_their_key(const std::string&, const VarMap& vars) override
         {
         return vars.get_req_bin("CounterKey");
         }
   };
BOTAN_REGISTER_TEST("pubkey", "curve25519_agreement", Curve25519_Agreement_Tests);

class Curve25519_Roundtrip_Test final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         for(size_t i = 0; i < 10; ++i)
            {
            Test::Result result("Curve25519 roundtrip");

            Botan::Curve25519_PrivateKey a_priv_gen(Test::rng());
            Botan::Curve25519_PrivateKey b_priv_gen(Test::rng());

#if defined(BOTAN_HAS_PKCS5_PBES2) && defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_AEAD_GCM) && defined(BOTAN_HAS_SHA2_32)
            // Then serialize to encrypted storage

            const std::string a_pass = "alice pass";
            const std::string b_pass = "bob pass";
            const auto pbe_time = std::chrono::milliseconds(10);
            const std::string a_priv_pem = Botan::PKCS8::PEM_encode(a_priv_gen, Test::rng(), a_pass, pbe_time);
            const std::string b_priv_pem = Botan::PKCS8::PEM_encode(b_priv_gen, Test::rng(), b_pass, pbe_time);

            // Reload back into memory
            Botan::DataSource_Memory a_priv_ds(a_priv_pem);
            Botan::DataSource_Memory b_priv_ds(b_priv_pem);

            std::unique_ptr<Botan::Private_Key> a_priv(Botan::PKCS8::load_key(a_priv_ds, Test::rng(), [a_pass]() { return a_pass; }));
            std::unique_ptr<Botan::Private_Key> b_priv(Botan::PKCS8::load_key(b_priv_ds, Test::rng(), b_pass));
#else
            const std::string a_priv_pem = Botan::PKCS8::PEM_encode(a_priv_gen);
            const std::string b_priv_pem = Botan::PKCS8::PEM_encode(b_priv_gen);

            // Reload back into memory
            Botan::DataSource_Memory a_priv_ds(a_priv_pem);
            Botan::DataSource_Memory b_priv_ds(b_priv_pem);

            std::unique_ptr<Botan::Private_Key> a_priv(Botan::PKCS8::load_key(a_priv_ds, Test::rng()));
            std::unique_ptr<Botan::Private_Key> b_priv(Botan::PKCS8::load_key(b_priv_ds, Test::rng()));
#endif

            // Export public keys as PEM
            const std::string a_pub_pem = Botan::X509::PEM_encode(*a_priv);
            const std::string b_pub_pem = Botan::X509::PEM_encode(*b_priv);

            Botan::DataSource_Memory a_pub_ds(a_pub_pem);
            Botan::DataSource_Memory b_pub_ds(b_pub_pem);

            std::unique_ptr<Botan::Public_Key> a_pub(Botan::X509::load_key(a_pub_ds));
            std::unique_ptr<Botan::Public_Key> b_pub(Botan::X509::load_key(b_pub_ds));

            Botan::Curve25519_PublicKey* a_pub_key = dynamic_cast<Botan::Curve25519_PublicKey*>(a_pub.get());
            Botan::Curve25519_PublicKey* b_pub_key = dynamic_cast<Botan::Curve25519_PublicKey*>(b_pub.get());

            if(a_pub_key && b_pub_key)
               {
               Botan::PK_Key_Agreement a_ka(*a_priv, Test::rng(), "Raw");
               Botan::PK_Key_Agreement b_ka(*b_priv, Test::rng(), "Raw");

               const std::string context = "shared context value";
               Botan::SymmetricKey a_key = a_ka.derive_key(32, b_pub_key->public_value(), context);
               Botan::SymmetricKey b_key = b_ka.derive_key(32, a_pub_key->public_value(), context);

               if(!result.test_eq("key agreement", a_key.bits_of(), b_key.bits_of()))
                  {
                  result.test_note(a_priv_pem);
                  result.test_note(b_priv_pem);
                  }
               }
            else
               {
               result.test_failure("Cast back to Curve25519 failed");
               }

            results.push_back(result);
            }

         return results;
         }
   };

BOTAN_REGISTER_TEST("pubkey", "curve25519_rt", Curve25519_Roundtrip_Test);

class Curve25519_Keygen_Tests final : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override
         {
         return { "" };
         }
      std::string algo_name() const override
         {
         return "Curve25519";
         }
   };

BOTAN_REGISTER_TEST("pubkey", "curve25519_keygen", Curve25519_Keygen_Tests);

#endif

}
