/*
* (C) 2009,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)

#include "test_rng.h"
#include "test_pubkey.h"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <memory>

#include <botan/oids.h>
#include <botan/x509_key.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/numthry.h>
#include <botan/hex.h>

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh.h>
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
  #include <botan/nr.h>
#endif

#if defined(BOTAN_HAS_RW)
  #include <botan/rw.h>
#endif

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elgamal.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_ECDH)
  #include <botan/ecdh.h>
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
  #include <botan/gost_3410.h>
#endif

#if defined(BOTAN_HAS_DLIES)
  #include <botan/dlies.h>
  #include <botan/kdf.h>
#endif

namespace Botan_Tests {

void check_invalid_signatures(Test::Result& result,
                              Botan::PK_Verifier& verifier,
                              const std::vector<uint8_t>& message,
                              const std::vector<uint8_t>& signature)
   {
   const std::vector<uint8_t> zero_sig(signature.size());
   result.test_eq("all zero signature invalid", verifier.verify_message(message, zero_sig), false);

   std::vector<uint8_t> bad_sig;
   for(size_t i = 0; i <= Test::soak_level(); ++i)
      {
      bad_sig = Test::mutate_vec(signature);

      if(!result.test_eq("incorrect signature invalid", verifier.verify_message(message, bad_sig), false))
         {
         result.test_note("Accepted invalid signature " + Botan::hex_encode(bad_sig));
         }
      }
   }

void check_invalid_ciphertexts(Test::Result& result,
                               Botan::PK_Decryptor& decryptor,
                               const std::vector<uint8_t>& plaintext,
                               const std::vector<uint8_t>& ciphertext)
   {
   std::vector<uint8_t> bad_ctext = ciphertext;

   size_t ciphertext_accepted = 0, ciphertext_rejected = 0;

   for(size_t i = 0; i <= Test::soak_level(); ++i)
      {
      size_t offset = Test::rng().get_random<uint16_t>() % bad_ctext.size();
      bad_ctext[offset] ^= Test::rng().next_nonzero_byte();

      try
         {
         const Botan::secure_vector<uint8_t> decrypted = decryptor.decrypt(bad_ctext);
         ++ciphertext_accepted;

         if(!result.test_ne("incorrect ciphertext different", decrypted, plaintext))
            {
            result.test_note("used corrupted ciphertext " + Botan::hex_encode(bad_ctext));
            }

         }
      catch(std::exception& e)
         {
         ++ciphertext_rejected;
         }
      }

   result.test_note("Accepted " + std::to_string(ciphertext_accepted) +
                    " invalid ciphertexts, rejected " + std::to_string(ciphertext_rejected));
   }

Test::Result
PK_Signature_Generation_Test::run_one_test(const std::string&, const VarMap& vars)
   {
   const std::vector<uint8_t> message   = get_req_bin(vars, "Msg");
   const std::vector<uint8_t> signature = get_req_bin(vars, "Signature");
   const std::string padding = get_opt_str(vars, "Padding", default_padding(vars));

   std::unique_ptr<Botan::RandomNumberGenerator> rng;
   if(vars.count("Nonce"))
      {
      rng.reset(new Fixed_Output_RNG(get_req_bin(vars, "Nonce")));
      }

   Test::Result result(algo_name() + "/" + padding + " signature generation");

   std::unique_ptr<Botan::Private_Key> privkey = load_private_key(vars);
   std::unique_ptr<Botan::Public_Key> pubkey(Botan::X509::load_key(Botan::X509::BER_encode(*privkey)));

   Botan::PK_Signer signer(*privkey, padding);
   Botan::PK_Verifier verifier(*pubkey, padding);

   const std::vector<uint8_t> generated_signature = signer.sign_message(message, rng ? *rng : Test::rng());
   result.test_eq("generated signature matches KAT", generated_signature, signature);

   result.test_eq("generated signature valid", verifier.verify_message(message, generated_signature), true);
   check_invalid_signatures(result, verifier, message, signature);
   result.test_eq("correct signature valid", verifier.verify_message(message, signature), true);

   return result;
   }

Test::Result
PK_Signature_Verification_Test::run_one_test(const std::string&, const VarMap& vars)
   {
   const std::vector<uint8_t> message   = get_req_bin(vars, "Msg");
   const std::vector<uint8_t> signature = get_req_bin(vars, "Signature");
   const std::string padding = get_opt_str(vars, "Padding", default_padding(vars));
   std::unique_ptr<Botan::Public_Key> pubkey = load_public_key(vars);

   Test::Result result(algo_name() + "/" + padding + " signature verification");

   Botan::PK_Verifier verifier(*pubkey, padding);

   result.test_eq("correct signature valid", verifier.verify_message(message, signature), true);

   check_invalid_signatures(result, verifier, message, signature);

   return result;
   }

Test::Result
PK_Encryption_Decryption_Test::run_one_test(const std::string&, const VarMap& vars)
   {
   const std::vector<uint8_t> plaintext  = get_req_bin(vars, "Msg");
   const std::vector<uint8_t> ciphertext = get_req_bin(vars, "Ciphertext");

   const std::string padding = get_opt_str(vars, "Padding", default_padding(vars));

   std::unique_ptr<Botan::RandomNumberGenerator> kat_rng;
   if(vars.count("Nonce"))
      {
      kat_rng.reset(new Fixed_Output_RNG(get_req_bin(vars, "Nonce")));
      }

   Test::Result result(algo_name() + "/" + padding + " decryption");

   std::unique_ptr<Botan::Private_Key> privkey = load_private_key(vars);

   // instead slice the private key to work around elgamal test inputs
   //std::unique_ptr<Botan::Public_Key> pubkey(Botan::X509::load_key(Botan::X509::BER_encode(*privkey)));

   Botan::PK_Encryptor_EME encryptor(*privkey, padding);
   result.test_eq("encryption", encryptor.encrypt(plaintext, kat_rng ? *kat_rng : Test::rng()), ciphertext);

   Botan::PK_Decryptor_EME decryptor(*privkey, padding);
   result.test_eq("decryption", decryptor.decrypt(ciphertext), plaintext);

   check_invalid_ciphertexts(result, decryptor, plaintext, ciphertext);

   return result;
   }

Test::Result PK_Key_Agreement_Test::run_one_test(const std::string&, const VarMap& vars)
   {
   const std::vector<uint8_t> shared = get_req_bin(vars, "K");
   const std::string kdf = get_opt_str(vars, "KDF", default_kdf(vars));

   Test::Result result(algo_name() + "/" + kdf + " key agreement");

   std::unique_ptr<Botan::Private_Key> privkey = load_our_key(vars);
   const std::vector<uint8_t> pubkey = load_their_key(vars);

   const size_t key_len = get_opt_sz(vars, "OutLen", 0);

   Botan::PK_Key_Agreement kas(*privkey, kdf);

   result.test_eq("agreement", kas.derive_key(key_len, pubkey).bits_of(), shared);

   return result;
   }

namespace {

class PK_Keygen_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         const std::vector<std::string> modp_groups = { "modp/ietf/1024",
                                                        "modp/ietf/2048",
                                                        "dsa/jce/1024" };
         const std::vector<std::string> dsa_groups = { "dsa/jce/1024", "dsa/botan/2048" };

         const std::vector<std::string> ecdsa_groups = { "secp256r1", "secp256k1", "secp384r1", "secp521r1" };
         const std::vector<std::string> gost_groups = { "gost_256A", "secp256r1" };

         std::vector<Test::Result> results;

#if defined(BOTAN_HAS_RSA)
         results.push_back(test_key("RSA 1024", new Botan::RSA_PrivateKey(Test::rng(), 1024)));
#endif

#if defined(BOTAN_HAS_RW)
         results.push_back(test_key("RW 1024", new Botan::RW_PrivateKey(Test::rng(), 1024)));
#endif

         for(auto&& group_name : modp_groups)
            {
            Botan::DL_Group group(group_name);
#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
            results.push_back(test_key("DH " + group_name, new Botan::DH_PrivateKey(Test::rng(), group)));
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
            results.push_back(test_key("NR " + group_name, new Botan::NR_PrivateKey(Test::rng(), group)));
#endif
            }

#if defined(BOTAN_HAS_DSA)
         for(auto&& group_name : dsa_groups)
            {
            Botan::DL_Group group(group_name);
            results.push_back(test_key("DSA " + group_name,
                                       new Botan::DSA_PrivateKey(Test::rng(), group)));
            }
#endif

         for(auto&& group_name : ecdsa_groups)
            {
            Botan::EC_Group group(group_name);

#if defined(BOTAN_HAS_ECDSA)
            results.push_back(test_key("ECDSA " + group_name,
                                       new Botan::ECDSA_PrivateKey(Test::rng(), group)));
#endif

#if defined(BOTAN_HAS_ECDH)
            results.push_back(test_key("ECDH " + group_name,
                                       new Botan::ECDH_PrivateKey(Test::rng(), group)));
#endif
            }

#if defined(BOTAN_HAS_GOST_34_10_2001)
         for(auto&& group_name : gost_groups)
            {
            results.push_back(test_key("GOST 34.10 " + group_name,
                                       new Botan::GOST_3410_PrivateKey(Test::rng(), Botan::EC_Group(group_name))));
            }
#endif

         return results;
         }

   private:
         Test::Result test_key(const std::string& algo, Botan::Private_Key* keyp)
         {
         std::unique_ptr<Botan::Private_Key> key(keyp); // assume ownership

         Test::Result result(algo + " keygen");

         const std::string pub_pem = Botan::X509::PEM_encode(*key);

         try
            {
            Botan::DataSource_Memory input_pub(pub_pem);
            std::unique_ptr<Botan::Public_Key> restored_pub(Botan::X509::load_key(input_pub));

            result.test_eq("recovered public key from private", restored_pub.get(), true);

            result.test_eq("public key has same type", restored_pub->algo_name(), key->algo_name());

            result.test_eq("public key passes checks", restored_pub->check_key(Test::rng(), false), true);
            }
         catch(std::exception& e)
            {
            result.test_failure("roundtrip public key", e.what());
            }

         const std::string priv_pem = Botan::PKCS8::PEM_encode(*key);

         try
            {
            Botan::DataSource_Memory input_priv(priv_pem);
            std::unique_ptr<Botan::Private_Key> restored_priv(
               Botan::PKCS8::load_key(input_priv, Test::rng()));

            result.test_eq("recovered private key from blob", restored_priv.get(), true);

            result.test_eq("reloaded key has same type", restored_priv->algo_name(), key->algo_name());

            result.test_eq("private key passes checks", restored_priv->check_key(Test::rng(), false), true);
            }
         catch(std::exception& e)
            {
            result.test_failure("roundtrip private key", e.what());
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("pk_keygen", PK_Keygen_Tests);

}

}

#endif

size_t test_pk_keygen()
   {
   return Botan_Tests::basic_error_report("pk_keygen");
   }
