/*
* (C) 2009,2015 Jack Lloyd
* (C) 2017 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_pubkey.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)

   #include "test_rng.h"

   #include <botan/data_src.h>
   #include <botan/hex.h>
   #include <botan/pk_algs.h>
   #include <botan/pkcs8.h>
   #include <botan/pubkey.h>
   #include <botan/x509_key.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/stl_util.h>

   #if defined(BOTAN_HAS_HMAC_DRBG)
      #include <botan/hmac_drbg.h>
   #endif

   #include <array>

namespace Botan_Tests {

namespace {

void check_invalid_signatures(Test::Result& result,
                              Botan::PK_Verifier& verifier,
                              const std::vector<uint8_t>& message,
                              const std::vector<uint8_t>& signature,
                              Botan::RandomNumberGenerator& rng) {
   const size_t tests_to_run = (Test::run_long_tests() ? 20 : 5);

   const std::vector<uint8_t> zero_sig(signature.size());
   result.test_eq("all zero signature invalid", verifier.verify_message(message, zero_sig), false);

   for(size_t i = 0; i < tests_to_run; ++i) {
      const std::vector<uint8_t> bad_sig = Test::mutate_vec(signature, rng);

      try {
         if(!result.test_eq("incorrect signature invalid", verifier.verify_message(message, bad_sig), false)) {
            result.test_note("Accepted invalid signature " + Botan::hex_encode(bad_sig));
         }
      } catch(std::exception& e) {
         result.test_note("Accepted invalid signature " + Botan::hex_encode(bad_sig));
         result.test_failure("Modified signature rejected with exception", e.what());
      }
   }
}

}  // namespace

// Exposed for DLIES tests
void check_invalid_ciphertexts(Test::Result& result,
                               Botan::PK_Decryptor& decryptor,
                               const std::vector<uint8_t>& plaintext,
                               const std::vector<uint8_t>& ciphertext,
                               Botan::RandomNumberGenerator& rng) {
   const size_t tests_to_run = (Test::run_long_tests() ? 20 : 5);

   size_t ciphertext_accepted = 0, ciphertext_rejected = 0;

   for(size_t i = 0; i < tests_to_run; ++i) {
      const std::vector<uint8_t> bad_ctext = Test::mutate_vec(ciphertext, rng);

      try {
         const Botan::secure_vector<uint8_t> decrypted = decryptor.decrypt(bad_ctext);
         ++ciphertext_accepted;

         if(!result.test_ne("incorrect ciphertext different", decrypted, plaintext)) {
            result.test_eq("used corrupted ciphertext", bad_ctext, ciphertext);
         }
      } catch(std::exception&) {
         ++ciphertext_rejected;
      }
   }

   result.test_note("Accepted " + std::to_string(ciphertext_accepted) + " invalid ciphertexts, rejected " +
                    std::to_string(ciphertext_rejected));
}

std::string PK_Test::choose_padding(const VarMap& vars, const std::string& pad_hdr) {
   if(!pad_hdr.empty()) {
      return pad_hdr;
   }
   return vars.get_opt_str("Padding", this->default_padding(vars));
}

std::vector<std::string> PK_Test::possible_providers(const std::string& /*params*/) {
   return Test::provider_filter({"base", "commoncrypto", "openssl", "tpm"});
}

Test::Result PK_Signature_Generation_Test::run_one_test(const std::string& pad_hdr, const VarMap& vars) {
   const std::vector<uint8_t> message = vars.get_req_bin("Msg");
   const std::vector<uint8_t> signature = vars.get_req_bin("Signature");
   const std::string padding = choose_padding(vars, pad_hdr);

   std::ostringstream test_name;
   test_name << algo_name();
   if(vars.has_key("Group")) {
      test_name << "-" << vars.get_req_str("Group");
   }
   test_name << "/" << padding << " signature generation";

   Test::Result result(test_name.str());

   std::unique_ptr<Botan::Private_Key> privkey;
   try {
      privkey = load_private_key(vars);
   } catch(Botan::Lookup_Error& e) {
      result.note_missing(e.what());
      return result;
   }

   result.confirm("private key claims to support signatures",
                  privkey->supports_operation(Botan::PublicKeyOperation::Signature));

   auto pubkey = Botan::X509::load_key(Botan::X509::BER_encode(*privkey->public_key()));

   result.confirm("public key claims to support signatures",
                  pubkey->supports_operation(Botan::PublicKeyOperation::Signature));

   std::vector<std::unique_ptr<Botan::PK_Verifier>> verifiers;

   for(const auto& verify_provider : possible_providers(algo_name())) {
      std::unique_ptr<Botan::PK_Verifier> verifier;

      try {
         verifier =
            std::make_unique<Botan::PK_Verifier>(*pubkey, padding, Botan::Signature_Format::Standard, verify_provider);
      } catch(Botan::Lookup_Error&) {
         //result.test_note("Skipping verifying with " + verify_provider);
         continue;
      }

      result.test_eq("KAT signature valid", verifier->verify_message(message, signature), true);

      check_invalid_signatures(result, *verifier, message, signature, this->rng());

      result.test_eq("KAT signature valid (try 2)", verifier->verify_message(message, signature), true);

      verifiers.push_back(std::move(verifier));
   }

   for(const auto& sign_provider : possible_providers(algo_name())) {
      std::unique_ptr<Botan::PK_Signer> signer;

      std::vector<uint8_t> generated_signature;

      try {
         signer = std::make_unique<Botan::PK_Signer>(
            *privkey, this->rng(), padding, Botan::Signature_Format::Standard, sign_provider);

         if(vars.has_key("Nonce")) {
            auto rng = test_rng(vars.get_req_bin("Nonce"));
            generated_signature = signer->sign_message(message, *rng);
         } else {
            generated_signature = signer->sign_message(message, this->rng());
         }

         result.test_lte(
            "Generated signature within announced bound", generated_signature.size(), signer->signature_length());
      } catch(Botan::Lookup_Error&) {
         //result.test_note("Skipping signing with " + sign_provider);
         continue;
      }

      if(sign_provider == "base") {
         result.test_eq("generated signature matches KAT", generated_signature, signature);
      } else if(generated_signature != signature) {
         for(std::unique_ptr<Botan::PK_Verifier>& verifier : verifiers) {
            if(!result.test_eq(
                  "generated signature valid", verifier->verify_message(message, generated_signature), true)) {
               result.test_failure("generated signature", generated_signature);
            }
         }
      }
   }

   return result;
}

Botan::Signature_Format PK_Signature_Verification_Test::sig_format() const {
   return Botan::Signature_Format::Standard;
}

Test::Result PK_Signature_Verification_Test::run_one_test(const std::string& pad_hdr, const VarMap& vars) {
   const std::vector<uint8_t> message = vars.get_req_bin("Msg");
   const std::vector<uint8_t> signature = vars.get_req_bin("Signature");
   const std::string padding = choose_padding(vars, pad_hdr);

   const bool expected_valid = (vars.get_opt_sz("Valid", 1) == 1);

   auto pubkey = load_public_key(vars);

   std::ostringstream result_name;
   result_name << algo_name();
   if(vars.has_key("Group")) {
      result_name << "-" << vars.get_req_str("Group");
   }
   if(!padding.empty()) {
      result_name << "/" << padding;
   }
   result_name << " signature verification";
   Test::Result result(result_name.str());

   result.confirm("public key claims to support signatures",
                  pubkey->supports_operation(Botan::PublicKeyOperation::Signature));

   for(const auto& verify_provider : possible_providers(algo_name())) {
      std::unique_ptr<Botan::PK_Verifier> verifier;

      try {
         verifier = std::make_unique<Botan::PK_Verifier>(*pubkey, padding, sig_format(), verify_provider);
      } catch(Botan::Lookup_Error&) {
         //result.test_note("Skipping verifying with " + verify_provider);
      }

      if(verifier) {
         try {
            const bool verified = verifier->verify_message(message, signature);

            if(expected_valid) {
               result.test_eq("correct signature valid with " + verify_provider, verified, true);

               if(test_random_invalid_sigs()) {
                  check_invalid_signatures(result, *verifier, message, signature, this->rng());
               }
            } else {
               result.confirm("incorrect signature is rejected", verified == false);
            }
         } catch(std::exception& e) {
            result.test_failure("verification threw exception", e.what());
         }
      }
   }

   return result;
}

Test::Result PK_Signature_NonVerification_Test::run_one_test(const std::string& pad_hdr, const VarMap& vars) {
   const std::string padding = choose_padding(vars, pad_hdr);
   const std::vector<uint8_t> message = vars.get_req_bin("Msg");
   auto pubkey = load_public_key(vars);

   const std::vector<uint8_t> invalid_signature = vars.get_req_bin("InvalidSignature");

   Test::Result result(algo_name() + "/" + padding + " verify invalid signature");

   for(const auto& verify_provider : possible_providers(algo_name())) {
      std::unique_ptr<Botan::PK_Verifier> verifier;

      try {
         verifier =
            std::make_unique<Botan::PK_Verifier>(*pubkey, padding, Botan::Signature_Format::Standard, verify_provider);
         result.test_eq("incorrect signature rejected", verifier->verify_message(message, invalid_signature), false);
      } catch(Botan::Lookup_Error&) {
         result.test_note("Skipping verifying with " + verify_provider);
      }
   }

   return result;
}

std::vector<Test::Result> PK_Sign_Verify_DER_Test::run() {
   const std::vector<uint8_t> message = {'f', 'o', 'o', 'b', 'a', 'r'};
   const std::string padding = m_padding;

   auto privkey = key();
   if(!privkey) {
      return {};
   }
   auto pubkey = privkey->public_key();

   Test::Result result(algo_name() + "/" + padding + " signature sign/verify using DER format");

   for(const auto& provider : possible_providers(algo_name())) {
      std::unique_ptr<Botan::PK_Signer> signer;
      std::unique_ptr<Botan::PK_Verifier> verifier;

      try {
         signer = std::make_unique<Botan::PK_Signer>(
            *privkey, this->rng(), padding, Botan::Signature_Format::DerSequence, provider);
         verifier =
            std::make_unique<Botan::PK_Verifier>(*pubkey, padding, Botan::Signature_Format::DerSequence, provider);
      } catch(Botan::Lookup_Error& e) {
         result.test_note("Skipping sign/verify with " + provider, e.what());
      }

      if(signer && verifier) {
         try {
            std::vector<uint8_t> generated_signature = signer->sign_message(message, this->rng());
            const bool verified = verifier->verify_message(message, generated_signature);

            result.test_eq("correct signature valid with " + provider, verified, true);

            if(test_random_invalid_sigs()) {
               check_invalid_signatures(result, *verifier, message, generated_signature, this->rng());
            }
         } catch(std::exception& e) {
            result.test_failure("verification threw exception", e.what());
         }
      }
   }

   return {result};
}

std::vector<std::string> PK_Sign_Verify_DER_Test::possible_providers(const std::string& algo) {
   std::vector<std::string> pk_provider =
      Botan::probe_provider_private_key(algo, {"base", "commoncrypto", "openssl", "tpm"});
   return Test::provider_filter(pk_provider);
}

Test::Result PK_Encryption_Decryption_Test::run_one_test(const std::string& pad_hdr, const VarMap& vars) {
   const std::vector<uint8_t> plaintext = vars.get_req_bin("Msg");
   const std::vector<uint8_t> ciphertext = vars.get_req_bin("Ciphertext");
   const std::string padding = choose_padding(vars, pad_hdr);

   Test::Result result(algo_name() + (padding.empty() ? padding : "/" + padding) + " encryption");

   auto privkey = load_private_key(vars);

   result.confirm("private key claims to support encryption",
                  privkey->supports_operation(Botan::PublicKeyOperation::Encryption));

   // instead slice the private key to work around elgamal test inputs
   //auto pubkey = Botan::X509::load_key(Botan::X509::BER_encode(*privkey));
   Botan::Public_Key* pubkey = privkey.get();

   std::vector<std::unique_ptr<Botan::PK_Decryptor>> decryptors;

   for(const auto& dec_provider : possible_providers(algo_name())) {
      std::unique_ptr<Botan::PK_Decryptor> decryptor;

      try {
         decryptor = std::make_unique<Botan::PK_Decryptor_EME>(*privkey, this->rng(), padding, dec_provider);
      } catch(Botan::Lookup_Error&) {
         continue;
      }

      Botan::secure_vector<uint8_t> decrypted;
      try {
         decrypted = decryptor->decrypt(ciphertext);

         result.test_lte("Plaintext within length", decrypted.size(), decryptor->plaintext_length(ciphertext.size()));
      } catch(Botan::Exception& e) {
         result.test_failure("Failed to decrypt KAT ciphertext", e.what());
      }

      result.test_eq(dec_provider, "decryption of KAT", decrypted, plaintext);
      check_invalid_ciphertexts(result, *decryptor, plaintext, ciphertext, this->rng());
   }

   for(const auto& enc_provider : possible_providers(algo_name())) {
      std::unique_ptr<Botan::PK_Encryptor> encryptor;

      try {
         encryptor = std::make_unique<Botan::PK_Encryptor_EME>(*pubkey, this->rng(), padding, enc_provider);
      } catch(Botan::Lookup_Error&) {
         continue;
      }

      std::unique_ptr<Botan::RandomNumberGenerator> kat_rng;
      if(vars.has_key("Nonce")) {
         kat_rng = test_rng(vars.get_req_bin("Nonce"));
      }

      if(padding == "Raw") {
         /*
         Hack for RSA with no padding since sometimes one more bit will fit in but maximum_input_size
         rounds down to nearest byte
         */
         result.test_lte("Input within accepted bounds", plaintext.size(), encryptor->maximum_input_size() + 1);
      } else {
         result.test_lte("Input within accepted bounds", plaintext.size(), encryptor->maximum_input_size());
      }

      const std::vector<uint8_t> generated_ciphertext = encryptor->encrypt(plaintext, kat_rng ? *kat_rng : this->rng());

      result.test_lte(
         "Ciphertext within length", generated_ciphertext.size(), encryptor->ciphertext_length(plaintext.size()));

      if(enc_provider == "base") {
         result.test_eq(enc_provider, "generated ciphertext matches KAT", generated_ciphertext, ciphertext);
      } else if(generated_ciphertext != ciphertext) {
         for(std::unique_ptr<Botan::PK_Decryptor>& dec : decryptors) {
            result.test_eq("decryption of generated ciphertext", dec->decrypt(generated_ciphertext), plaintext);
         }
      }
   }

   return result;
}

Test::Result PK_Decryption_Test::run_one_test(const std::string& pad_hdr, const VarMap& vars) {
   const std::vector<uint8_t> plaintext = vars.get_req_bin("Msg");
   const std::vector<uint8_t> ciphertext = vars.get_req_bin("Ciphertext");
   const std::string padding = choose_padding(vars, pad_hdr);

   Test::Result result(algo_name() + (padding.empty() ? padding : "/" + padding) + " decryption");

   auto privkey = load_private_key(vars);

   for(const auto& dec_provider : possible_providers(algo_name())) {
      std::unique_ptr<Botan::PK_Decryptor> decryptor;

      try {
         decryptor = std::make_unique<Botan::PK_Decryptor_EME>(*privkey, this->rng(), padding, dec_provider);
      } catch(Botan::Lookup_Error&) {
         continue;
      }

      Botan::secure_vector<uint8_t> decrypted;
      try {
         decrypted = decryptor->decrypt(ciphertext);
      } catch(Botan::Exception& e) {
         result.test_failure("Failed to decrypt KAT ciphertext", e.what());
      }

      result.test_eq(dec_provider, "decryption of KAT", decrypted, plaintext);
      check_invalid_ciphertexts(result, *decryptor, plaintext, ciphertext, this->rng());
   }

   return result;
}

Test::Result PK_KEM_Test::run_one_test(const std::string& /*header*/, const VarMap& vars) {
   const std::vector<uint8_t> K = vars.get_req_bin("K");
   const std::vector<uint8_t> C0 = vars.get_req_bin("C0");
   const std::vector<uint8_t> salt = vars.get_opt_bin("Salt");
   const std::string kdf = vars.get_req_str("KDF");

   Test::Result result(algo_name() + "/" + kdf + " KEM");

   auto privkey = load_private_key(vars);

   result.confirm("private key claims to support KEM",
                  privkey->supports_operation(Botan::PublicKeyOperation::KeyEncapsulation));

   const Botan::Public_Key& pubkey = *privkey;

   const size_t desired_key_len = K.size();

   std::unique_ptr<Botan::PK_KEM_Encryptor> enc;
   try {
      enc = std::make_unique<Botan::PK_KEM_Encryptor>(pubkey, kdf);
   } catch(Botan::Lookup_Error&) {
      result.test_note("Skipping due to missing KDF: " + kdf);
      return result;
   }

   Fixed_Output_RNG fixed_output_rng(vars.get_req_bin("R"));

   const auto kem_result = enc->encrypt(fixed_output_rng, desired_key_len, salt);

   result.test_eq("encapsulated key length matches expected",
                  kem_result.encapsulated_shared_key().size(),
                  enc->encapsulated_key_length());

   result.test_eq(
      "shared key length matches expected", kem_result.shared_key().size(), enc->shared_key_length(desired_key_len));

   result.test_eq("C0 matches", kem_result.encapsulated_shared_key(), C0);
   result.test_eq("K matches", kem_result.shared_key(), K);

   std::unique_ptr<Botan::PK_KEM_Decryptor> dec;
   try {
      dec = std::make_unique<Botan::PK_KEM_Decryptor>(*privkey, this->rng(), kdf);
   } catch(Botan::Lookup_Error& e) {
      result.test_note("Skipping test", e.what());
      return result;
   }

   result.test_eq("encapsulated key length matches expected",
                  kem_result.encapsulated_shared_key().size(),
                  dec->encapsulated_key_length());

   const Botan::secure_vector<uint8_t> decr_shared_key =
      dec->decrypt(C0.data(), C0.size(), desired_key_len, salt.data(), salt.size());

   result.test_eq(
      "shared key length matches expected", decr_shared_key.size(), dec->shared_key_length(desired_key_len));

   result.test_eq("decrypted K matches", decr_shared_key, K);

   return result;
}

Test::Result PK_Key_Agreement_Test::run_one_test(const std::string& header, const VarMap& vars) {
   const std::vector<uint8_t> shared = vars.get_req_bin("K");
   const std::string kdf = vars.get_opt_str("KDF", default_kdf(vars));

   Test::Result result(algo_name() + "/" + kdf + (header.empty() ? header : " " + header) + " key agreement");

   auto privkey = load_our_key(header, vars);

   result.confirm("private key claims to support key agreement",
                  privkey->supports_operation(Botan::PublicKeyOperation::KeyAgreement));

   const std::vector<uint8_t> pubkey = load_their_key(header, vars);

   const size_t key_len = vars.get_opt_sz("OutLen", 0);

   for(const auto& provider : possible_providers(algo_name())) {
      std::unique_ptr<Botan::PK_Key_Agreement> kas;

      try {
         kas = std::make_unique<Botan::PK_Key_Agreement>(*privkey, this->rng(), kdf, provider);

         if(agreement_should_fail(header, vars)) {
            result.test_throws("key agreement fails", [&] { kas->derive_key(key_len, pubkey); });
         } else {
            auto derived_key = kas->derive_key(key_len, pubkey).bits_of();
            result.test_eq(provider, "agreement", derived_key, shared);

            if(key_len == 0 && kdf == "Raw") {
               result.test_eq("Expected size", derived_key.size(), kas->agreed_value_size());
            }
         }
      } catch(Botan::Lookup_Error&) {
         //result.test_note("Skipping key agreement with with " + provider);
      }
   }

   return result;
}

std::vector<std::string> PK_Key_Generation_Test::possible_providers(const std::string& algo) {
   std::vector<std::string> pk_provider =
      Botan::probe_provider_private_key(algo, {"base", "commoncrypto", "openssl", "tpm"});
   return Test::provider_filter(pk_provider);
}

namespace {

   #if defined(BOTAN_HAS_PKCS5_PBES2) && defined(BOTAN_HAS_AES) && \
      (defined(BOTAN_HAS_SHA2_32) || defined(BOTAN_HAS_SCRYPT))
void test_pbe_roundtrip(Test::Result& result,
                        const Botan::Private_Key& key,
                        const std::string& pbe_algo,
                        Botan::RandomNumberGenerator& rng) {
   const auto pkcs8 = key.private_key_info();

   auto passphrase = Test::random_password(rng);

   try {
      Botan::DataSource_Memory data_src(
         Botan::PKCS8::PEM_encode(key, rng, passphrase, std::chrono::milliseconds(1), pbe_algo));

      auto loaded = Botan::PKCS8::load_key(data_src, passphrase);

      result.confirm("recovered private key from encrypted blob", loaded != nullptr);
      result.test_eq("reloaded key has same type", loaded->algo_name(), key.algo_name());
      result.test_eq("reloaded key has same encoding", loaded->private_key_info(), pkcs8);
   } catch(std::exception& e) {
      result.test_failure("roundtrip encrypted PEM private key", e.what());
   }

   try {
      Botan::DataSource_Memory data_src(
         Botan::PKCS8::BER_encode(key, rng, passphrase, std::chrono::milliseconds(1), pbe_algo));

      auto loaded = Botan::PKCS8::load_key(data_src, passphrase);

      result.confirm("recovered private key from BER blob", loaded != nullptr);
      result.test_eq("reloaded key has same type", loaded->algo_name(), key.algo_name());
      result.test_eq("reloaded key has same encoding", loaded->private_key_info(), pkcs8);
   } catch(std::exception& e) {
      result.test_failure("roundtrip encrypted BER private key", e.what());
   }
}
   #endif

}  // namespace

std::vector<Test::Result> PK_Key_Generation_Test::run() {
   std::vector<Test::Result> results;

   for(const auto& param : keygen_params()) {
      const auto algo = algo_name(param);
      const std::string report_name = Botan::fmt("{}{}", algo, (param.empty() ? param : " " + param));

      Test::Result result(report_name + " keygen");

      const std::vector<std::string> providers = possible_providers(algo);

      if(providers.empty()) {
         result.note_missing("provider key generation " + algo);
      }

      result.start_timer();
      for(auto&& prov : providers) {
         auto key_p = Botan::create_private_key(algo, this->rng(), param, prov);

         if(key_p == nullptr) {
            continue;
         }

         const Botan::Private_Key& key = *key_p;

         try {
            result.confirm("Key passes self tests", key.check_key(this->rng(), true));
         } catch(Botan::Lookup_Error&) {}

         const std::string name = key.algo_name();
         result.confirm("Key has a non-empty name", !name.empty());

         if(auto oid = Botan::OID::from_name(name)) {
            result.test_success("Keys name maps to an OID");

            result.test_eq("Keys name OID is the same as the object oid",
                           oid.value().to_string(),
                           key.object_identifier().to_string());
         } else {
            const bool exception = name == "Kyber" || name == "ML-KEM" || name == "ML-DSA" || name == "SLH-DSA" ||
                                   name == "FrodoKEM" || name == "SPHINCS+" || name == "ClassicMcEliece";
            if(!exception) {
               result.test_failure("Keys name " + name + " does not map to an OID");
            }
         }

         result.test_gte("Key has reasonable estimated strength (lower)", key.estimated_strength(), 64);
         result.test_lt("Key has reasonable estimated strength (upper)", key.estimated_strength(), 512);

         auto public_key = key.public_key();

         result.test_eq("public_key has same name", public_key->algo_name(), key.algo_name());

         result.test_eq(
            "public_key has same encoding", Botan::X509::PEM_encode(key), Botan::X509::PEM_encode(*public_key));

         // Test generation of another key pair from a given (abstract) asymmetric key
         // KEX algorithms must support that (so that we can generate ephemeral keys in
         // an abstract fashion). For other algorithms it's a nice-to-have.
         try {
            auto sk2 = public_key->generate_another(this->rng());
            auto pk2 = sk2->public_key();

            result.test_eq("new private key has the same name", sk2->algo_name(), key.algo_name());
            result.test_eq("new public key has the same name", pk2->algo_name(), public_key->algo_name());
            result.test_eq(
               "new private key has the same est. strength", sk2->estimated_strength(), key.estimated_strength());
            result.test_eq("new public key has the same est. strength",
                           pk2->estimated_strength(),
                           public_key->estimated_strength());
            result.test_ne("new private keys are different keys", sk2->private_key_bits(), key.private_key_bits());
         } catch(const Botan::Not_Implemented&) {
            result.confirm("KEX algorithms are required to implement 'generate_another'",
                           !public_key->supports_operation(Botan::PublicKeyOperation::KeyAgreement));
         }

         // Test that the raw public key can be encoded. This is not supported
         // by all algorithms; we expect Not_Implemented for these.
         const std::vector<std::string> algos_that_dont_have_a_raw_encoding = {"RSA"};
         try {
            auto raw = public_key->raw_public_key_bits();
            result.test_ne("raw_public_key_bits is not empty", raw.size(), 0);

            if(public_key->supports_operation(Botan::PublicKeyOperation::KeyAgreement)) {
               // For KEX algorithms, raw_public_key_bits must be equal to the canonical
               // public value obtained by PK_Key_Agreement_Key::public_value().
               const auto* ka_key = dynamic_cast<const Botan::PK_Key_Agreement_Key*>(&key);
               result.require("is a key agreement private key", ka_key != nullptr);
               result.test_eq("public_key_bits has same encoding", raw, ka_key->public_value());
            }

            if(auto raw_pk = public_key_from_raw(param, prov, raw)) {
               result.test_eq("public_key has same type", raw_pk->algo_name(), public_key->algo_name());
               result.test_eq("public_key has same encoding", raw_pk->public_key_bits(), public_key->public_key_bits());
            }
         } catch(const Botan::Not_Implemented&) {
            if(!Botan::value_exists(algos_that_dont_have_a_raw_encoding, public_key->algo_name())) {
               result.test_failure("raw_public_key_bits not implemented for " + public_key->algo_name());
            } else {
               result.test_note("raw_public_key_bits threw Not_Implemented as expected for " + public_key->algo_name());
            }
         }

         // Test PEM public key round trips OK
         try {
            Botan::DataSource_Memory data_src(Botan::X509::PEM_encode(key));
            auto loaded = Botan::X509::load_key(data_src);

            result.confirm("recovered public key from private", loaded != nullptr);
            result.test_eq("public key has same type", loaded->algo_name(), key.algo_name());

            try {
               result.test_eq("public key passes checks", loaded->check_key(this->rng(), false), true);
            } catch(Botan::Lookup_Error&) {}
         } catch(std::exception& e) {
            result.test_failure("roundtrip PEM public key", e.what());
         }

         // Test DER public key round trips OK
         try {
            const auto ber = key.subject_public_key();
            Botan::DataSource_Memory data_src(ber);
            auto loaded = Botan::X509::load_key(data_src);

            result.confirm("recovered public key from private", loaded != nullptr);
            result.test_eq("public key has same type", loaded->algo_name(), key.algo_name());
            result.test_eq("public key has same encoding", loaded->subject_public_key(), ber);
         } catch(std::exception& e) {
            result.test_failure("roundtrip BER public key", e.what());
         }

         // Test PEM private key round trips OK
         try {
            const auto ber = key.private_key_info();
            Botan::DataSource_Memory data_src(ber);
            auto loaded = Botan::PKCS8::load_key(data_src);

            result.confirm("recovered private key from PEM blob", loaded != nullptr);
            result.test_eq("reloaded key has same type", loaded->algo_name(), key.algo_name());
            result.test_eq("reloaded key has same encoding", loaded->private_key_info(), ber);
         } catch(std::exception& e) {
            result.test_failure("roundtrip PEM private key", e.what());
         }

         try {
            Botan::DataSource_Memory data_src(Botan::PKCS8::BER_encode(key));
            auto loaded = Botan::PKCS8::load_key(data_src);

            result.confirm("recovered public key from private", loaded != nullptr);
            result.test_eq("public key has same type", loaded->algo_name(), key.algo_name());
         } catch(std::exception& e) {
            result.test_failure("roundtrip BER private key", e.what());
         }

   #if defined(BOTAN_HAS_PKCS5_PBES2) && defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_SHA2_32)

         test_pbe_roundtrip(result, key, "PBE-PKCS5v20(AES-128/CBC,SHA-256)", this->rng());
   #endif

   #if defined(BOTAN_HAS_PKCS5_PBES2) && defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_SCRYPT)

         test_pbe_roundtrip(result, key, "PBES2(AES-128/CBC,Scrypt)", this->rng());
   #endif
      }

      result.end_timer();

      results.push_back(result);
   }

   return results;
}

Test::Result PK_Key_Validity_Test::run_one_test(const std::string& header, const VarMap& vars) {
   Test::Result result(algo_name() + " key validity");

   if(header != "Valid" && header != "Invalid") {
      throw Test_Error("Unexpected header for PK_Key_Validity_Test");
   }

   const bool expected_valid = (header == "Valid");
   auto pubkey = load_public_key(vars);

   const bool tested_valid = pubkey->check_key(this->rng(), true);

   result.test_eq("Expected validation result", expected_valid, tested_valid);

   return result;
}

PK_Key_Generation_Stability_Test::PK_Key_Generation_Stability_Test(const std::string& algo,
                                                                   const std::string& test_src) :
      PK_Test(algo, test_src, "Rng,RngSeed,Key", "KeyParams,RngParams") {}

Test::Result PK_Key_Generation_Stability_Test::run_one_test(const std::string&, const VarMap& vars) {
   const std::string key_param = vars.get_opt_str("KeyParams", "");
   const std::string rng_algo = vars.get_req_str("Rng");
   const std::string rng_params = vars.get_opt_str("RngParams", "");
   const std::vector<uint8_t> rng_seed = vars.get_req_bin("RngSeed");
   const std::vector<uint8_t> expected_key = vars.get_req_bin("Key");

   std::ostringstream report_name;

   report_name << algo_name();
   if(!key_param.empty()) {
      report_name << " " << key_param;
   }
   report_name << " keygen stability";

   Test::Result result(report_name.str());

   result.start_timer();

   std::unique_ptr<Botan::RandomNumberGenerator> rng;

   #if defined(BOTAN_HAS_HMAC_DRBG)
   if(rng_algo == "HMAC_DRBG") {
      rng = std::make_unique<Botan::HMAC_DRBG>(rng_params);
   }
   #endif

   if(rng_algo == "Fixed") {
      if(!rng_params.empty()) {
         throw Test_Error("Expected empty RngParams for Fixed RNG");
      }
      rng = std::make_unique<Fixed_Output_RNG>();
   }

   if(rng) {
      rng->add_entropy(rng_seed.data(), rng_seed.size());

      try {
         auto key = Botan::create_private_key(algo_name(), *rng, key_param);
         if(key) {
            const auto key_bits = key->private_key_info();
            result.test_eq("Generated key matched expected value", key_bits, expected_key);
         }
      } catch(Botan::Exception& e) {
         result.test_note("failed to create key", e.what());
      }
   } else {
      result.test_note("Skipping test due to unavailable RNG");
   }

   result.end_timer();

   return result;
}

/**
 * @brief Some general tests for minimal API sanity for signing/verification.
 */
class PK_API_Sign_Test : public Text_Based_Test {
   public:
      PK_API_Sign_Test() : Text_Based_Test("pubkey/api_sign.vec", "AlgoParams,SigParams", "Provider") {}

   protected:
      Test::Result run_one_test(const std::string& algorithm, const VarMap& vars) final {
         const std::string algo_params = vars.get_req_str("AlgoParams");
         const std::string sig_params = vars.get_req_str("SigParams");
         const std::string verify_params = vars.get_opt_str("VerifyParams", sig_params);
         const std::string provider = vars.get_opt_str("Provider", "base");

         std::ostringstream test_name;
         test_name << "Sign/verify API tests " << algorithm;
         if(!algo_params.empty()) {
            test_name << '(' << algo_params << ')';
         }
         if(!sig_params.empty()) {
            test_name << '/' << sig_params;
         }
         Test::Result result(test_name.str());

         auto privkey = [&]() -> std::unique_ptr<Botan::Private_Key> {
            try {
               return Botan::create_private_key(algorithm, this->rng(), algo_params, provider);
            } catch(Botan::Not_Implemented&) {}

            return nullptr;
         }();

         if(!privkey) {
            result.test_note(Botan::fmt(
               "Skipping Sign/verify API tests for {}({}) with provider {}", algorithm, algo_params, provider));
            return result;
         }

         auto pubkey = Botan::X509::load_key(Botan::X509::BER_encode(*privkey));
         result.confirm("Storing and loading public key works", pubkey != nullptr);

         result.confirm("private key claims to support signatures",
                        privkey->supports_operation(Botan::PublicKeyOperation::Signature));
         result.confirm("public key claims to support signatures",
                        pubkey->supports_operation(Botan::PublicKeyOperation::Signature));
         result.test_gt("Public key length must be greater than 0", privkey->key_length(), 0);
         if(privkey->stateful_operation()) {
            result.confirm("A stateful key reports the number of remaining operations",
                           privkey->remaining_operations().has_value());
         } else {
            result.confirm("A stateless key has an unlimited number of remaining operations",
                           !privkey->remaining_operations().has_value());
         }

         auto signer = std::make_unique<Botan::PK_Signer>(
            *privkey, this->rng(), sig_params, Botan::Signature_Format::Standard, provider);
         auto verifier =
            std::make_unique<Botan::PK_Verifier>(*pubkey, verify_params, Botan::Signature_Format::Standard, provider);
         result.confirm("Creating PK_Signer works", signer != nullptr);
         result.confirm("Creating PK_Signer works", verifier != nullptr);

         result.test_is_nonempty("PK_Signer should report some hash", signer->hash_function());
         result.test_is_nonempty("PK_Verifier should report some hash", verifier->hash_function());

         result.test_eq(
            "PK_Signer and PK_Verifier report the same hash", signer->hash_function(), verifier->hash_function());

         pubkey.reset();
         privkey.reset();
         const std::array<uint8_t, 4> msg{0xde, 0xad, 0xbe, 0xef};
         const auto sig = signer->sign_message(msg, this->rng());
         result.test_gt("Signer should still work if no one else hold a reference to the key", sig.size(), 0);
         result.test_eq("Verifier should still work if no one else hold a reference to the key",
                        verifier->verify_message(msg, sig),
                        true);

         return result;
      }

      bool skip_this_test([[maybe_unused]] const std::string& header, const VarMap&) override {
   #if !defined(BOTAN_HAS_SLH_DSA_WITH_SHA2)
         if(header == "SLH-DSA") {
            return true;
         }
   #endif
         return false;
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_api_sign", PK_API_Sign_Test);

/**
 * @brief Testing PK key decoding
 */
class PK_Key_Decoding_Test : public Text_Based_Test {
   public:
      PK_Key_Decoding_Test() : Text_Based_Test("pubkey/key_encoding.vec", "Key") {}

   protected:
      Test::Result run_one_test(const std::string&, const VarMap& vars) final {
         const auto key = vars.get_req_bin("Key");

         Test::Result result("PK Key Decoding");

         try {
            auto k = Botan::PKCS8::load_key(key);
            result.test_success("Was able to deserialize the key");
         } catch(Botan::Not_Implemented&) {
            result.test_note("Skipping test due to to algorithm being unavailable");
         } catch(Botan::Exception& e) {
            if(std::string(e.what()).starts_with("Unknown or unavailable public key algorithm")) {
               result.test_note("Skipping test due to to algorithm being unavailable");
            } else {
               result.test_failure("Failed to deserialize key", e.what());
            }
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_key_decoding", PK_Key_Decoding_Test);

}  // namespace Botan_Tests

#endif
