/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_RSA)
   #include "test_pubkey.h"
   #include "test_rng.h"
   #include <botan/der_enc.h>
   #include <botan/numthry.h>
   #include <botan/pk_options.h>
   #include <botan/pubkey.h>
   #include <botan/rsa.h>
   #include <botan/internal/blinding.h>
   #include <botan/internal/fmt.h>
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
         return Botan::fmt("PSS({},MGF1,{})", hash_name, salt_size);
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
         return Botan::fmt("PSS_Raw({},MGF1,{})", hash_name, salt_size);
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
            const Botan::RSA_PrivateKey rsa(rng, 1024);
            result.test_failure("Generated a key with a bad RNG");
         } catch(Botan::Internal_Error& e) {
            result.test_success("Key generation with bad RNG failed");
            result.test_str_eq("Expected message", e.what(), "Internal error: RNG failure during RSA key generation");
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
         const Botan::RSA_PrivateKey rsa(this->rng(), 1024);
         Botan::Null_RNG null_rng;
   #endif

   #if defined(BOTAN_HAS_EMSA_RAW)

         /*
         * The blinder chooses a new starting point Blinder::ReinitInterval
         * so sign several times that with a single key.
         *
         * Very small values (padding/hashing disabled, only low byte set on input)
         * are used as an additional test on the blinders.
         */

         // don't try this at home
         Botan::PK_Signer signer(rsa, this->rng(), Botan::PK_Signature_Options().with_padding("Raw"));
         Botan::PK_Verifier verifier(rsa, Botan::PK_Signature_Options().with_padding("Raw"));

         for(size_t i = 1; i <= Botan::Blinder::ReinitInterval * 6; ++i) {
            std::vector<uint8_t> input(16);
            input[input.size() - 1] = static_cast<uint8_t>(i | 1);

            signer.update(input);

            // assert RNG is not called in this situation
            std::vector<uint8_t> signature = signer.signature(null_rng);

            result.test_is_true("Signature verifies", verifier.verify_message(input, signature));
         }
   #endif

   #if defined(BOTAN_HAS_EME_RAW)

         /*
         * The blinder chooses a new starting point Blinder::ReinitInterval
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
         const size_t rng_bytes = rsa.get_n().bytes() + (2 * 8 * Botan::Blinder::ReinitInterval);

         Fixed_Output_RNG fixed_rng(this->rng(), rng_bytes);
         Botan::PK_Decryptor_EME decryptor(rsa, fixed_rng, "Raw", "base");

         for(size_t i = 1; i <= Botan::Blinder::ReinitInterval; ++i) {
            std::vector<uint8_t> input(16);
            input[input.size() - 1] = static_cast<uint8_t>(i);

            std::vector<uint8_t> ciphertext = encryptor.encrypt(input, null_rng);

            std::vector<uint8_t> plaintext = Botan::unlock(decryptor.decrypt(ciphertext));
            plaintext.insert(plaintext.begin(), input.size() - 1, 0);

            result.test_bin_eq("Successful decryption", plaintext, input);
         }

         result.test_is_false("RNG is no longer seeded", fixed_rng.is_seeded());

         // one more decryption should trigger a blinder reinitialization
         result.test_throws("RSA blinding reinit",
                            "Fixed output RNG ran out of bytes, test bug?",
                            [&decryptor, &encryptor, &null_rng]() {
                               std::vector<uint8_t> ciphertext =
                                  encryptor.encrypt(std::vector<uint8_t>(16, 5), null_rng);
                               decryptor.decrypt(ciphertext);
                            });

   #endif

         return std::vector<Test::Result>{result};
      }
};

class RSA_ISO9796_Roundtrip_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("RSA ISO-9796 sign/verify roundtrip");

         try {
            const Botan::RSA_PrivateKey rsa(this->rng(), 1024);

            // A leading-zero recovered representative occurs about 1/128 of the time
            constexpr size_t iterations = 256;

            for(const std::string padding : {"ISO_9796_DS2(SHA-256)", "ISO_9796_DS3(SHA-256)"}) {
               Botan::PK_Signer signer(rsa, this->rng(), padding);
               Botan::PK_Verifier verifier(rsa, padding);

               size_t verified = 0;
               for(size_t i = 0; i != iterations; ++i) {
                  const auto msg = rng().random_vec<std::vector<uint8_t>>(i);

                  const auto sig = signer.sign_message(msg, this->rng());
                  if(verifier.verify_message(msg, sig)) {
                     verified += 1;
                  }
               }

               result.test_sz_eq(padding + " signatures all verify", verified, iterations);
            }

            // ISO-9796-2 DS2/DS3 are message-recovery schemes: the verifier
            // must split the message at the same capacity the encoder used. A
            // modulus whose bit-length is not a multiple of 8 and a message that
            // fills the recoverable region exercise a capacity calculation that
            // previously differed by one byte between the two sides. Byte-aligned
            // moduli (e.g. 1024 above) hide it, so sweep every residue mod 8.
            const Botan::BigInt e = Botan::BigInt::from_u64(65537);
            const size_t p_bits = 512;
            const Botan::BigInt p = Botan::generate_rsa_prime(this->rng(), this->rng(), p_bits, e);
            for(size_t mod_bits = 1025; mod_bits <= 1031; ++mod_bits) {
               const size_t q_bits = mod_bits - p_bits;
               const Botan::BigInt q = Botan::generate_rsa_prime(this->rng(), this->rng(), q_bits, e);

               const Botan::RSA_PrivateKey rsa_unaligned(p, q, e);
               if(!result.test_sz_eq("modulus has expected bit length", rsa_unaligned.key_length(), mod_bits)) {
                  continue;
               }

               for(const std::string padding : {"ISO_9796_DS2(SHA-256)", "ISO_9796_DS3(SHA-256)"}) {
                  Botan::PK_Signer signer(rsa_unaligned, this->rng(), padding);
                  Botan::PK_Verifier verifier(rsa_unaligned, padding);

                  // Check inputs under, at and above the recoverable capacity
                  for(size_t msg_len = 0; msg_len != 128; ++msg_len) {
                     const auto msg = this->rng().random_vec<std::vector<uint8_t>>(msg_len);
                     const auto sig = signer.sign_message(msg, this->rng());
                     result.test_is_true(
                        Botan::fmt(
                           "{} verifies recovery message of length {} (modulus {} bits)", padding, msg_len, mod_bits),
                        verifier.verify_message(msg, sig));
                  }
               }
            }
         } catch(const Botan::Lookup_Error& e) {
            result.note_missing(e.what());
         }

         return {result};
      }
};

class RSA_DecryptOrRandom_Tests : public Test {
   public:
      std::vector<Test::Result> run() override {
         const std::vector<std::string> padding_schemes = {
   #if defined(BOTAN_HAS_EME_PKCS1)
            "PKCS1v15",
   #endif
   #if defined(BOTAN_HAS_EME_OAEP)
            "OAEP(SHA-256)",
   #endif
         };

         constexpr size_t bits = 1024;

         auto private_key = Botan::RSA_PrivateKey(rng(), bits);

         std::vector<Test::Result> results;
         for(const auto& padding : padding_schemes) {
            Test::Result result("RSA decrypt_or_random " + padding);
            test_decrypt_or_random(result, padding, private_key, rng());
            results.push_back(result);
         }
         return results;
      }

   private:
      static void test_decrypt_or_random(Test::Result& result,
                                         std::string_view padding,
                                         Botan::Private_Key& private_key,
                                         Botan::RandomNumberGenerator& rng) {
         constexpr size_t trials = 100;
         constexpr size_t pt_len = 32;

         auto public_key = private_key.public_key();
         const auto msg = rng.random_vec(pt_len);

         const Botan::PK_Encryptor_EME enc(*public_key, rng, padding);
         const auto ctext = enc.encrypt(msg, rng);

         const Botan::PK_Decryptor_EME dec(private_key, rng, padding);

         const BigInt modulus = public_key->get_int_field("n");
         const size_t modulus_bytes = modulus.bytes();

         for(size_t i = 0; i != trials; ++i) {
            auto bad_ctext = (BigInt::from_bytes(mutate_vec(ctext, rng, false, 0)) % modulus).serialize(modulus_bytes);

            const auto rec = dec.decrypt_or_random(bad_ctext.data(), bad_ctext.size(), pt_len, rng);

            result.test_sz_eq("Returns a ciphertext of expected length", rec.size(), pt_len);
         }

         // Test decrypt_or_random with content check happy path
         for(size_t i = 1; i != pt_len; ++i) {
            const size_t req_bytes = i;

            std::vector<uint8_t> required_contents(req_bytes);
            std::vector<uint8_t> required_offsets(req_bytes);

            for(size_t j = 0; j != req_bytes; ++j) {
               const uint8_t idx = rng.next_byte() % pt_len;
               required_contents[j] = msg[idx];
               required_offsets[j] = idx;
            }

            auto rec = dec.decrypt_or_random(
               ctext.data(), ctext.size(), pt_len, rng, required_contents.data(), required_offsets.data(), req_bytes);

            result.test_bin_eq("Returned the expected message", rec, msg);
         }

         // Test decrypt_or_random with content check error path
         for(size_t i = 1; i != pt_len; ++i) {
            const size_t req_bytes = i;

            std::vector<uint8_t> required_contents(req_bytes);
            std::vector<uint8_t> required_offsets(req_bytes);

            const size_t corrupted = Test::random_index(rng, req_bytes);
            const uint8_t corruption = rng.next_nonzero_byte();

            for(size_t j = 0; j != req_bytes; ++j) {
               const uint8_t idx = rng.next_byte() % pt_len;
               required_offsets[j] = idx;

               if(idx == corrupted) {
                  required_contents[j] = msg[idx] ^ corruption;
               } else {
                  required_contents[j] = msg[idx];
               }
            }

            auto rec = dec.decrypt_or_random(
               ctext.data(), ctext.size(), pt_len, rng, required_contents.data(), required_offsets.data(), req_bytes);

            result.test_bin_ne("Returned random message", rec, ctext);

            for(size_t j = 0; j != req_bytes; ++j) {
               result.test_is_true("Random message satisfies stated content requirements",
                                   rec[required_offsets[j]] == required_contents[j]);
            }
         }
      }
};

class RSA_Key_Validation_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("RSA private key validation");

         // 1024 bit primes where 65537 divides p-1 but not q-1
         const Botan::BigInt p(
            "0xf1b1af255213508dd961691d25047b97ff9fd7619ad159b6f884afc52e2a885c"
            "00a0fbe9666382faf5cf504a6fd2d11fa5d5058b22028aaf5d2bce64d2dfcbfc"
            "e5bdfebce48ce400fe16f305783a54fb7edcd7e5e5c7da1be5ba1ec88e51c0cc"
            "1aa46682d832dc3a0913fef98a64f56103113b1a6a30c635c177d8770583b5ef");

         const Botan::BigInt q(
            "0xd7904462a109946096a44637f08bea8d404bcc88aee03225f9b024a255f11587"
            "02c24b44bb133865e5d067a1f3afee30092ef1bc811c3170cac9982b8348ba65"
            "a1ddba64929fe08091481e292a2ddfba61f5ebc737cf1fd1eb54969aea924a46"
            "77a784c60f1aa938e92ff65c0eb7bdb36f6fd2c62fc5f1b19f968deac60f2ec3");

         const Botan::BigInt e65537 = Botan::BigInt::from_u64(65537);

         result.test_throws<Botan::Decoding_Error>("e dividing p-1 is rejected",
                                                   [&]() { const Botan::RSA_PrivateKey key(p, q, e65537); });

         // gcd(17, p-1) == gcd(17, q-1) == 1 so these primes are usable with e = 17
         const Botan::BigInt e = Botan::BigInt::from_u64(17);
         const Botan::RSA_PrivateKey key(p, q, e);
         result.test_is_true("Key with coprime exponent passes strong check", key.check_key(this->rng(), true));

         const Botan::BigInt& n = key.get_n();
         const Botan::BigInt& d = key.get_d();

         result.test_no_throw("Consistent d is accepted", [&]() { const Botan::RSA_PrivateKey ok(p, q, e, d, n); });

         result.test_throws<Botan::Decoding_Error>("Inconsistent d is rejected",
                                                   [&]() { const Botan::RSA_PrivateKey bad(p, q, e, d + 1, n); });

         result.test_throws<Botan::Decoding_Error>("Wrong modulus is rejected",
                                                   [&]() { const Botan::RSA_PrivateKey bad(p, q, e, d, n + 2); });

         // PKCS #1 RSAPrivateKey encoding with the given CRT components
         auto encode = [&](const Botan::BigInt& d_v,
                           const Botan::BigInt& d1_v,
                           const Botan::BigInt& d2_v,
                           const Botan::BigInt& c_v) -> std::vector<uint8_t> {
            std::vector<uint8_t> out;
            Botan::DER_Encoder(out)
               .start_sequence()
               .encode(static_cast<size_t>(0))
               .encode(n)
               .encode(e)
               .encode(d_v)
               .encode(p)
               .encode(q)
               .encode(d1_v)
               .encode(d2_v)
               .encode(c_v)
               .end_cons();
            return out;
         };

         const Botan::AlgorithmIdentifier alg_id("RSA", Botan::AlgorithmIdentifier::USE_NULL_PARAM);

         result.test_no_throw("Consistent encoding is accepted", [&]() {
            const Botan::RSA_PrivateKey ok(alg_id, encode(d, key.get_d1(), key.get_d2(), key.get_c()));
         });

         result.test_throws<Botan::Decoding_Error>("Encoding with altered d is rejected", [&]() {
            const Botan::RSA_PrivateKey bad(alg_id, encode(d + 1, key.get_d1(), key.get_d2(), key.get_c()));
         });

         result.test_throws<Botan::Decoding_Error>("Encoding with d >= n is rejected", [&]() {
            const Botan::RSA_PrivateKey bad(alg_id, encode(d + n, key.get_d1(), key.get_d2(), key.get_c()));
         });

         result.test_throws<Botan::Decoding_Error>("Encoding with zero d1 is rejected", [&]() {
            const Botan::RSA_PrivateKey bad(alg_id, encode(d, Botan::BigInt::zero(), key.get_d2(), key.get_c()));
         });

         result.test_throws<Botan::Decoding_Error>("Encoding with d2 >= q is rejected", [&]() {
            const Botan::RSA_PrivateKey bad(alg_id, encode(d, key.get_d1(), q, key.get_c()));
         });

         result.test_throws<Botan::Decoding_Error>("Encoding with c >= p is rejected", [&]() {
            const Botan::RSA_PrivateKey bad(alg_id, encode(d, key.get_d1(), key.get_d2(), p));
         });

         result.test_throws<Botan::Decoding_Error>("Encoding with negative c is rejected", [&]() {
            const Botan::RSA_PrivateKey bad(alg_id, encode(d, key.get_d1(), key.get_d2(), -key.get_c()));
         });

         return {result};
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
BOTAN_REGISTER_TEST("pubkey", "rsa_iso9796_roundtrip", RSA_ISO9796_Roundtrip_Tests);
BOTAN_REGISTER_TEST("pubkey", "rsa_decrypt_or_random", RSA_DecryptOrRandom_Tests);
BOTAN_REGISTER_TEST("pubkey", "rsa_key_validation", RSA_Key_Validation_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
