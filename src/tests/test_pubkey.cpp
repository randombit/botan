/*
* (C) 2009,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_pubkey.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)

#include "test_rng.h"

#include <botan/pubkey.h>
#include <botan/x509_key.h>
#include <botan/pkcs8.h>
#include <botan/oids.h>
#include <botan/hex.h>

namespace Botan_Tests {

namespace {

std::vector<std::string> possible_pk_providers()
   {
   return { "base", "openssl", "tpm" };
   }

}

void check_invalid_signatures(Test::Result& result,
                              Botan::PK_Verifier& verifier,
                              const std::vector<uint8_t>& message,
                              const std::vector<uint8_t>& signature)
   {
   const std::vector<uint8_t> zero_sig(signature.size());
   result.test_eq("all zero signature invalid", verifier.verify_message(message, zero_sig), false);

   std::vector<uint8_t> bad_sig = signature;

   for(size_t i = 0; i < Test::soak_level(); ++i)
      {
      while(bad_sig == signature)
         bad_sig = Test::mutate_vec(bad_sig, true);

      if(!result.test_eq("incorrect signature invalid",
                         verifier.verify_message(message, bad_sig), false))
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

   for(size_t i = 0; i < Test::soak_level(); ++i)
      {
      while(bad_ctext == ciphertext)
         bad_ctext = Test::mutate_vec(bad_ctext, true);

      try
         {
         const Botan::secure_vector<uint8_t> decrypted = decryptor.decrypt(bad_ctext);
         ++ciphertext_accepted;

         if(!result.test_ne("incorrect ciphertext different", decrypted, plaintext))
            {
            result.test_eq("used corrupted ciphertext", bad_ctext, ciphertext);
            }
         }
      catch(std::exception&)
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

   Test::Result result(algo_name() + "/" + padding + " signature generation");

   std::unique_ptr<Botan::Private_Key> privkey = load_private_key(vars);
   std::unique_ptr<Botan::Public_Key> pubkey(Botan::X509::load_key(Botan::X509::BER_encode(*privkey)));

   for(auto&& sign_provider : possible_pk_providers())
      {
      std::unique_ptr<Botan::PK_Signer> signer;

      try
         {
         signer.reset(new Botan::PK_Signer(*privkey, padding, Botan::IEEE_1363, sign_provider));
         }
      catch(Botan::Lookup_Error&)
         {
         //result.test_note("Skipping signing with " + sign_provider);
         continue;
         }

      std::unique_ptr<Botan::RandomNumberGenerator> rng;
      if(vars.count("Nonce"))
         {
         rng.reset(new Fixed_Output_RNG(get_req_bin(vars, "Nonce")));
         }

      const std::vector<uint8_t> generated_signature =
         signer->sign_message(message, rng ? *rng : Test::rng());

      if(sign_provider == "base")
         {
         result.test_eq("generated signature matches KAT", generated_signature, signature);
         }

      for(auto&& verify_provider : possible_pk_providers())
         {
         std::unique_ptr<Botan::PK_Verifier> verifier;

         try
            {
            verifier.reset(new Botan::PK_Verifier(*pubkey, padding, Botan::IEEE_1363, verify_provider));
            }
         catch(Botan::Lookup_Error&)
            {
            //result.test_note("Skipping verifying with " + verify_provider);
            continue;
            }

         if(!result.test_eq("generated signature valid",
                            verifier->verify_message(message, generated_signature), true))
            {
            result.test_failure("generated signature", generated_signature);
            }

         check_invalid_signatures(result, *verifier, message, signature);
         result.test_eq("KAT signature valid", verifier->verify_message(message, signature), true);
         }
      }

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

   for(auto&& verify_provider : possible_pk_providers())
      {
      std::unique_ptr<Botan::PK_Verifier> verifier;

      try
         {
         verifier.reset(new Botan::PK_Verifier(*pubkey, padding, Botan::IEEE_1363, verify_provider));
         result.test_eq("correct signature valid", verifier->verify_message(message, signature), true);
         check_invalid_signatures(result, *verifier, message, signature);
         }
      catch(Botan::Lookup_Error&)
         {
         result.test_note("Skipping verifying with " + verify_provider);
         }
      }

   return result;
   }

Test::Result
PK_Encryption_Decryption_Test::run_one_test(const std::string&, const VarMap& vars)
   {
   const std::vector<uint8_t> plaintext  = get_req_bin(vars, "Msg");
   const std::vector<uint8_t> ciphertext = get_req_bin(vars, "Ciphertext");

   const std::string padding = get_opt_str(vars, "Padding", default_padding(vars));

   Test::Result result(algo_name() + "/" + padding + " decryption");

   std::unique_ptr<Botan::Private_Key> privkey = load_private_key(vars);

   // instead slice the private key to work around elgamal test inputs
   //std::unique_ptr<Botan::Public_Key> pubkey(Botan::X509::load_key(Botan::X509::BER_encode(*privkey)));
   Botan::Public_Key* pubkey = privkey.get();

   for(auto&& enc_provider : possible_pk_providers())
      {
      std::unique_ptr<Botan::PK_Encryptor> encryptor;

      try
         {
         encryptor.reset(new Botan::PK_Encryptor_EME(*pubkey, padding, enc_provider));
         }
      catch(Botan::Lookup_Error&)
         {
         //result.test_note("Skipping encryption with provider " + enc_provider);
         continue;
         }

      std::unique_ptr<Botan::RandomNumberGenerator> kat_rng;
      if(vars.count("Nonce"))
         {
         kat_rng.reset(new Fixed_Output_RNG(get_req_bin(vars, "Nonce")));
         }

      const std::vector<uint8_t> generated_ciphertext =
         encryptor->encrypt(plaintext, kat_rng ? *kat_rng : Test::rng());

      if(enc_provider == "base")
         {
         result.test_eq(enc_provider, "generated ciphertext matches KAT",
                        generated_ciphertext, ciphertext);
         }

      for(auto&& dec_provider : possible_pk_providers())
         {
         std::unique_ptr<Botan::PK_Decryptor> decryptor;

         try
            {
            decryptor.reset(new Botan::PK_Decryptor_EME(*privkey, padding, dec_provider));
            }
         catch(Botan::Lookup_Error&)
            {
            //result.test_note("Skipping decryption with provider " + dec_provider);
            continue;
            }

         result.test_eq(dec_provider, "decryption of KAT", decryptor->decrypt(ciphertext), plaintext);
         check_invalid_ciphertexts(result, *decryptor, plaintext, ciphertext);

         if(generated_ciphertext != ciphertext)
            {
            result.test_eq(dec_provider, "decryption of generated ciphertext",
                           decryptor->decrypt(generated_ciphertext), plaintext);
            }
         }
      }

   return result;
   }

Test::Result PK_KEM_Test::run_one_test(const std::string&, const VarMap& vars)
   {
   const std::vector<uint8_t> K = get_req_bin(vars, "K");
   const std::vector<uint8_t> C0 = get_req_bin(vars, "C0");
   const std::vector<uint8_t> salt = get_opt_bin(vars, "Salt");
   const std::string kdf = get_req_str(vars, "KDF");

   Test::Result result(algo_name() + "/" + kdf + " KEM");

   std::unique_ptr<Botan::Private_Key> privkey = load_private_key(vars);

   const Botan::Public_Key& pubkey = *privkey;

   const size_t desired_key_len = K.size();

   std::unique_ptr<Botan::PK_KEM_Encryptor> enc;
   try
      {
      enc.reset(new Botan::PK_KEM_Encryptor(pubkey, kdf));
      }
   catch(Botan::Lookup_Error&)
      {
      return result;
      }

   Fixed_Output_RNG fixed_output_rng(get_req_bin(vars, "R"));

   Botan::secure_vector<byte> produced_encap_key, shared_key;
   enc->encrypt(produced_encap_key,
                shared_key,
                desired_key_len,
                fixed_output_rng,
                salt);

   result.test_eq("C0 matches", produced_encap_key, C0);
   result.test_eq("K matches", shared_key, K);

   std::unique_ptr<Botan::PK_KEM_Decryptor> dec;
   try
      {
      dec.reset(new Botan::PK_KEM_Decryptor(*privkey, kdf));
      }
   catch(Botan::Lookup_Error&)
      {
      return result;
      }

   const Botan::secure_vector<uint8_t> decr_shared_key =
      dec->decrypt(C0.data(), C0.size(),
                   desired_key_len,
                   salt.data(),
                   salt.size());

   result.test_eq("decrypted K matches", decr_shared_key, K);

   return result;
   }

Test::Result PK_Key_Agreement_Test::run_one_test(const std::string& header, const VarMap& vars)
   {
   const std::vector<uint8_t> shared = get_req_bin(vars, "K");
   const std::string kdf = get_opt_str(vars, "KDF", default_kdf(vars));

   Test::Result result(algo_name() + "/" + kdf +
                       (header.empty() ? header : " " + header) +
                       " key agreement");

   std::unique_ptr<Botan::Private_Key> privkey = load_our_key(header, vars);
   const std::vector<uint8_t> pubkey = load_their_key(header, vars);

   const size_t key_len = get_opt_sz(vars, "OutLen", 0);

   for(auto&& provider : possible_pk_providers())
      {
      std::unique_ptr<Botan::PK_Key_Agreement> kas;

      try
         {
         kas.reset(new Botan::PK_Key_Agreement(*privkey, kdf, provider));
         result.test_eq(provider, "agreement", kas->derive_key(key_len, pubkey).bits_of(), shared);
         }
      catch(Botan::Lookup_Error&)
         {
         //result.test_note("Skipping key agreement with with " + provider);
         }
      }

   return result;
   }

std::vector<Test::Result> PK_Key_Generation_Test::run()
   {
   std::vector<Test::Result> results;

   for(auto&& param : keygen_params())
      {
      std::unique_ptr<Botan::Private_Key> key = make_key(Test::rng(), param);

      const std::string report_name = key->algo_name() + (param.empty() ? param : " " + param);

      results.push_back(test_key(report_name, *key));
      }
   return results;
   }

Test::Result
PK_Key_Generation_Test::test_key(const std::string& algo, const Botan::Private_Key& key)
   {
   Test::Result result(algo + " keygen");

   try
      {
      Botan::DataSource_Memory data_src(Botan::X509::PEM_encode(key));
      std::unique_ptr<Botan::Public_Key> loaded(Botan::X509::load_key(data_src));

      result.test_eq("recovered public key from private", loaded.get(), true);
      result.test_eq("public key has same type", loaded->algo_name(), key.algo_name());
      result.test_eq("public key passes checks", loaded->check_key(Test::rng(), false), true);
      }
   catch(std::exception& e)
      {
      result.test_failure("roundtrip PEM public key", e.what());
      }

   try
      {
      Botan::DataSource_Memory data_src(Botan::X509::BER_encode(key));
      std::unique_ptr<Botan::Public_Key> loaded(Botan::X509::load_key(data_src));

      result.test_eq("recovered public key from private", loaded.get(), true);
      result.test_eq("public key has same type", loaded->algo_name(), key.algo_name());
      result.test_eq("public key passes checks", loaded->check_key(Test::rng(), false), true);
      }
   catch(std::exception& e)
      {
      result.test_failure("roundtrip BER public key", e.what());
      }

   try
      {
      Botan::DataSource_Memory data_src(Botan::PKCS8::PEM_encode(key));
      std::unique_ptr<Botan::Private_Key> loaded(
         Botan::PKCS8::load_key(data_src, Test::rng()));

      result.test_eq("recovered private key from PEM blob", loaded.get(), true);
      result.test_eq("reloaded key has same type", loaded->algo_name(), key.algo_name());
      result.test_eq("private key passes checks", loaded->check_key(Test::rng(), false), true);
      }
   catch(std::exception& e)
      {
      result.test_failure("roundtrip PEM private key", e.what());
      }

   try
      {
      Botan::DataSource_Memory data_src(Botan::PKCS8::BER_encode(key));
      std::unique_ptr<Botan::Public_Key> loaded(Botan::PKCS8::load_key(data_src, Test::rng()));

      result.test_eq("recovered public key from private", loaded.get(), true);
      result.test_eq("public key has same type", loaded->algo_name(), key.algo_name());
      result.test_eq("public key passes checks", loaded->check_key(Test::rng(), false), true);
      }
   catch(std::exception& e)
      {
      result.test_failure("roundtrip BER private key", e.what());
      }

   const std::string passphrase = Test::random_password();

   try
      {
      Botan::DataSource_Memory data_src(
         Botan::PKCS8::PEM_encode(key, Test::rng(), passphrase,
                                  std::chrono::milliseconds(10)));

      std::unique_ptr<Botan::Private_Key> loaded(
         Botan::PKCS8::load_key(data_src, Test::rng(), passphrase));

      result.test_eq("recovered private key from encrypted blob", loaded.get(), true);
      result.test_eq("reloaded key has same type", loaded->algo_name(), key.algo_name());
      result.test_eq("private key passes checks", loaded->check_key(Test::rng(), false), true);
      }
   catch(std::exception& e)
      {
      result.test_failure("roundtrip encrypted PEM private key", e.what());
      }

   try
      {
      Botan::DataSource_Memory data_src(
         Botan::PKCS8::BER_encode(key, Test::rng(), passphrase,
                                  std::chrono::milliseconds(10)));

      std::unique_ptr<Botan::Private_Key> loaded(
         Botan::PKCS8::load_key(data_src, Test::rng(), passphrase));

      result.test_eq("recovered private key from BER blob", loaded.get(), true);
      result.test_eq("reloaded key has same type", loaded->algo_name(), key.algo_name());
      result.test_eq("private key passes checks", loaded->check_key(Test::rng(), false), true);
      }
   catch(std::exception& e)
      {
      result.test_failure("roundtrip encrypted BER private key", e.what());
      }

   return result;
   }

}

#endif
