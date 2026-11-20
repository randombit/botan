/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PKCS5_PBES2) && defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_ED25519)
   #include <botan/ber_dec.h>
   #include <botan/pk_algs.h>
   #include <botan/pkcs8.h>
   #include <botan/internal/pbes2.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_PKCS5_PBES2) && defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_ED25519)

namespace {

constexpr std::string_view PBES2_MAC_Failure = "PBES2: Incorrect password or the ciphertext was modified";

class PKCS8_PBES2_MAC_Vector_Tests final : public Text_Based_Test {
   public:
      PKCS8_PBES2_MAC_Vector_Tests() :
            Text_Based_Test("pubkey/pkcs8_pbes2_mac.vec", "Passphrase,Encrypted", "PrivateKey,Plaintext") {}

      bool skip_this_test(const std::string& header, const VarMap& /*vars*/) override {
   #if defined(BOTAN_HAS_AEAD_GCM)
         constexpr bool have_gcm = true;
   #else
         constexpr bool have_gcm = false;
   #endif
         return header == "ValidGCM" && !have_gcm;
      }

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         Test::Result result("PKCS #8 PBES2 MAC " + header);

         const auto passphrase = vars.get_req_str("Passphrase");
         const auto encrypted = vars.get_req_bin("Encrypted");

         if(header == "ValidPadding") {
            Botan::AlgorithmIdentifier pbes2;
            std::vector<uint8_t> ctext;
            Botan::BER_Decoder(encrypted)
               .start_sequence()
               .decode(pbes2)
               .decode(ctext, Botan::ASN1_Type::OctetString)
               .end_cons();
            const auto plaintext = Botan::pbes2_decrypt(ctext, passphrase, pbes2.parameters());
            result.test_bin_eq("Decrypted plaintext", plaintext, vars.get_req_bin("Plaintext"));
         } else if(header == "Valid" || header == "ValidGCM") {
            const auto expected = Botan::PKCS8::load_key(vars.get_req_bin("PrivateKey"));

            try {
               const auto key = Botan::PKCS8::load_key(encrypted, passphrase);
               result.test_bin_eq("Decrypted key", key->private_key_info(), expected->private_key_info());
            } catch(std::exception& e) {
               result.test_failure("Loading valid key failed", e.what());
            }
         } else {
            try {
               Botan::PKCS8::load_key(encrypted, passphrase);
               result.test_failure("Accepted invalid key");
            } catch(std::exception& e) {
               result.test_str_contains("Expected error", e.what(), PBES2_MAC_Failure);
            }
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "pkcs8_pbes2_mac_vectors", PKCS8_PBES2_MAC_Vector_Tests);

std::vector<uint8_t> pbes2_salt(const Botan::AlgorithmIdentifier& pbes2) {
   Botan::AlgorithmIdentifier kdf;
   Botan::AlgorithmIdentifier cipher;
   Botan::BER_Decoder(pbes2.parameters()).start_sequence().decode(kdf).decode(cipher).end_cons();

   std::vector<uint8_t> salt;
   Botan::BER_Decoder(kdf.parameters()).start_sequence().decode(salt, Botan::ASN1_Type::OctetString);
   return salt;
}

class PKCS8_PBES2_MAC_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         const auto key = Botan::create_private_key("Ed25519", rng());
         const auto passphrase = Test::random_password(rng());

         results.push_back(test_cbc_has_mac(*key, passphrase, "AES-256/CBC", "SHA-256"));
   #if defined(BOTAN_HAS_SCRYPT)
         results.push_back(test_cbc_has_mac(*key, passphrase, "AES-256/CBC", "Scrypt"));
   #endif
   #if defined(BOTAN_HAS_DES)
         results.push_back(test_cbc_has_mac(*key, passphrase, "TripleDES/CBC", "SHA-256"));
   #endif
         results.push_back(test_modifications_rejected(*key, passphrase));
   #if defined(BOTAN_HAS_AEAD_GCM)
         results.push_back(test_gcm_has_no_mac(*key, passphrase));
   #endif

         return results;
      }

   private:
      Test::Result test_cbc_has_mac(const Botan::Private_Key& key,
                                    const std::string& passphrase,
                                    const std::string& cipher,
                                    const std::string& digest) {
         Test::Result result("PKCS #8 PBES2 MAC with " + cipher + " and " + digest);

         const auto encrypted =
            Botan::PKCS8::BER_encode_encrypted_pbkdf_iter(key, rng(), passphrase, 1000, cipher, digest);

         Botan::AlgorithmIdentifier pbes2;
         std::vector<uint8_t> ctext;
         Botan::BER_Decoder(encrypted)
            .start_sequence()
            .decode(pbes2)
            .decode(ctext, Botan::ASN1_Type::OctetString)
            .end_cons();

         const auto salt = pbes2_salt(pbes2);
         result.test_sz_eq("Salt length", salt.size(), 33);
         result.test_bin_eq("Salt label", std::span{salt}.first(16), "426F74616E20504B43532338204D4143");

         const auto pki = Botan::pbes2_decrypt(ctext, passphrase, pbes2.parameters());
         const auto orig_pki = key.private_key_info();
         result.test_sz_eq("PrivateKeyInfo grew by the size of the attribute", pki.size(), orig_pki.size() + 68);
         result.test_sz_eq("Salt encodes the padding length", salt.at(16), ctext.size() - pki.size());

         // [0] { SEQUENCE { 1.3.6.1.4.1.25258.5.1, SET { SEQUENCE { hmacWithSHA256 NULL, OCTET STRING (32) } } } }
         result.test_bin_eq("MAC attribute",
                            std::span{pki}.last(68).first(36),
                            "A042304006 0A2B0601040181C52A0501 3132 3030 300C06082A864886F70D02090500 0420");

         const auto loaded = Botan::PKCS8::load_key(encrypted, passphrase);
         result.test_bin_eq("Loaded key", loaded->private_key_info(), orig_pki);

         return result;
      }

      Test::Result test_modifications_rejected(const Botan::Private_Key& key, const std::string& passphrase) {
         Test::Result result("PKCS #8 PBES2 MAC rejects modifications");

         const auto encrypted =
            Botan::PKCS8::BER_encode_encrypted_pbkdf_iter(key, rng(), passphrase, 1000, "AES-256/CBC", "SHA-256");

         const auto loads = [&](std::span<const uint8_t> data) {
            try {
               Botan::PKCS8::load_key(data, passphrase);
               return true;
            } catch(std::exception&) {
               return false;
            }
         };

         result.test_is_true("Unmodified key loads", loads(encrypted));

         size_t accepted = 0;
         for(size_t i = 0; i != encrypted.size(); ++i) {
            auto modified = encrypted;
            modified[i] ^= static_cast<uint8_t>(1 << (i % 8));
            if(loads(modified)) {
               accepted += 1;
            }
         }

         result.test_sz_eq("Modified keys accepted", accepted, 0);

         Botan::AlgorithmIdentifier pbes2;
         std::vector<uint8_t> ctext;
         Botan::BER_Decoder(encrypted)
            .start_sequence()
            .decode(pbes2)
            .decode(ctext, Botan::ASN1_Type::OctetString)
            .end_cons();

         result.test_throws("Wrong password", PBES2_MAC_Failure, [&] {
            Botan::pbes2_decrypt(ctext, passphrase + "wrong", pbes2.parameters());
         });

         for(size_t len : {0, 1, 15, 16, 32, 64, 127}) {
            result.test_throws("Truncated ciphertext", PBES2_MAC_Failure, [&] {
               Botan::pbes2_decrypt(std::span{ctext}.first(len), passphrase, pbes2.parameters());
            });
         }
         return result;
      }

   #if defined(BOTAN_HAS_AEAD_GCM)
      Test::Result test_gcm_has_no_mac(const Botan::Private_Key& key, const std::string& passphrase) {
         Test::Result result("PKCS #8 PBES2 MAC not used with GCM");

         const auto encrypted =
            Botan::PKCS8::BER_encode_encrypted_pbkdf_iter(key, rng(), passphrase, 1000, "AES-256/GCM", "SHA-256");

         Botan::AlgorithmIdentifier pbes2;
         Botan::BER_Decoder(encrypted).start_sequence().decode(pbes2);
         result.test_sz_eq("Salt length", pbes2_salt(pbes2).size(), 16);

         const auto loaded = Botan::PKCS8::load_key(encrypted, passphrase);
         result.test_bin_eq("Loaded key", loaded->private_key_info(), key.private_key_info());

         return result;
      }
   #endif
};

BOTAN_REGISTER_TEST("pubkey", "pkcs8_pbes2_mac", PKCS8_PBES2_MAC_Tests);

}  // namespace

#endif

}  // namespace Botan_Tests
