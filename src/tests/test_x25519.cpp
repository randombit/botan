/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X25519)
   #include "test_pubkey.h"
   #include <botan/data_src.h>
   #include <botan/pkcs8.h>
   #include <botan/x25519.h>
   #include <botan/x509_key.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_X25519)

class X25519_Agreement_Tests final : public PK_Key_Agreement_Test {
   public:
      X25519_Agreement_Tests() : PK_Key_Agreement_Test("X25519", "pubkey/x25519.vec", "Secret,CounterKey,K") {}

      bool agreement_should_fail(const std::string& /*unused*/, const VarMap& vars) const override {
         for(const auto byte : vars.get_req_bin("K")) {
            if(byte != 0) {
               return false;
            }
         }

         return true;
      }

      std::string default_kdf(const VarMap& /*unused*/) const override { return "Raw"; }

      std::unique_ptr<Botan::Private_Key> load_our_key(const std::string& /*header*/, const VarMap& vars) override {
         const std::vector<uint8_t> secret_vec = vars.get_req_bin("Secret");
         Botan::secure_vector<uint8_t> secret(secret_vec.begin(), secret_vec.end());
         return std::make_unique<Botan::X25519_PrivateKey>(secret);
      }

      std::vector<uint8_t> load_their_key(const std::string& /*header*/, const VarMap& vars) override {
         return vars.get_req_bin("CounterKey");
      }
};

BOTAN_REGISTER_TEST("pubkey", "x25519_agreement", X25519_Agreement_Tests);

class X25519_Roundtrip_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         for(size_t i = 0; i < 10; ++i) {
            Test::Result result("X25519 roundtrip");

            Botan::X25519_PrivateKey a_priv_gen(this->rng());
            Botan::X25519_PrivateKey b_priv_gen(this->rng());

   #if defined(BOTAN_HAS_PKCS5_PBES2) && defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_AEAD_GCM) && \
      defined(BOTAN_HAS_SHA2_32)
            // Then serialize to encrypted storage

            const std::string a_pass = "alice pass";
            const std::string b_pass = "bob pass";
            const auto pbe_time = std::chrono::milliseconds(1);
            const std::string a_priv_pem = Botan::PKCS8::PEM_encode(a_priv_gen, this->rng(), a_pass, pbe_time);
            const std::string b_priv_pem = Botan::PKCS8::PEM_encode(b_priv_gen, this->rng(), b_pass, pbe_time);

            // Reload back into memory
            Botan::DataSource_Memory a_priv_ds(a_priv_pem);
            Botan::DataSource_Memory b_priv_ds(b_priv_pem);

            auto a_priv = Botan::PKCS8::load_key(a_priv_ds, [a_pass]() { return std::string(a_pass); });
            auto b_priv = Botan::PKCS8::load_key(b_priv_ds, b_pass);
   #else
            const std::string a_priv_pem = Botan::PKCS8::PEM_encode(a_priv_gen);
            const std::string b_priv_pem = Botan::PKCS8::PEM_encode(b_priv_gen);

            // Reload back into memory
            Botan::DataSource_Memory a_priv_ds(a_priv_pem);
            Botan::DataSource_Memory b_priv_ds(b_priv_pem);

            auto a_priv = Botan::PKCS8::load_key(a_priv_ds);
            auto b_priv = Botan::PKCS8::load_key(b_priv_ds);
   #endif

            // Export public keys as PEM
            const std::string a_pub_pem = Botan::X509::PEM_encode(*a_priv);
            const std::string b_pub_pem = Botan::X509::PEM_encode(*b_priv);

            Botan::DataSource_Memory a_pub_ds(a_pub_pem);
            Botan::DataSource_Memory b_pub_ds(b_pub_pem);

            auto a_pub = Botan::X509::load_key(a_pub_ds);
            auto b_pub = Botan::X509::load_key(b_pub_ds);

            Botan::X25519_PublicKey* a_pub_key = dynamic_cast<Botan::X25519_PublicKey*>(a_pub.get());
            Botan::X25519_PublicKey* b_pub_key = dynamic_cast<Botan::X25519_PublicKey*>(b_pub.get());

            if(a_pub_key && b_pub_key) {
               Botan::PK_Key_Agreement a_ka(*a_priv, this->rng(), "Raw");
               Botan::PK_Key_Agreement b_ka(*b_priv, this->rng(), "Raw");

               Botan::SymmetricKey a_key = a_ka.derive_key(32, b_pub_key->public_value());
               Botan::SymmetricKey b_key = b_ka.derive_key(32, a_pub_key->public_value());

               if(!result.test_eq("key agreement", a_key.bits_of(), b_key.bits_of())) {
                  result.test_note(a_priv_pem);
                  result.test_note(b_priv_pem);
               }
            } else {
               result.test_failure("Cast back to X25519 failed");
            }

            results.push_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("pubkey", "x25519_rt", X25519_Roundtrip_Test);

class X25519_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override { return {""}; }

      std::string algo_name() const override { return "X25519"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view /* keygen_params */,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         return std::make_unique<Botan::X25519_PublicKey>(raw_pk);
      }
};

BOTAN_REGISTER_TEST("pubkey", "x25519_keygen", X25519_Keygen_Tests);

#endif

}  // namespace Botan_Tests
