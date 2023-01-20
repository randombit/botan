/*
 * Tests for Crystals Dilithium
 * - KAT tests using the KAT vectors from
 *   https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/Dilithium-Round3.zip
 *
 * (C) 2022 Jack Lloyd
 * (C) 2022 Manuel Glaser, Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "test_rng.h"
#include "tests.h"

#if defined(BOTAN_HAS_DILITHIUM_COMMON)
   #include <botan/block_cipher.h>
   #include <botan/dilithium.h>
   #include <botan/oids.h>
   #include <botan/pubkey.h>
   #include <botan/pk_algs.h>
   #include <botan/hash.h>

   #include "test_pubkey.h"
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_DILITHIUM_COMMON)

namespace
{
   // Test Dilithium RNG class is used to get the correct randomness source for KAT tests
   class Dilithium_Test_RNG final : public Botan::RandomNumberGenerator
   {
   public:
      std::string name() const override { return "Dilithium_Test_RNG"; }
   //    key - 256-bit AES key
   //    ctr - a 128-bit plaintext value
   //    buffer - a 128-bit ciphertext value
   void AES256_ECB(unsigned char* key, unsigned char* ctr, unsigned char* buffer)
   {
      auto cipher(Botan::BlockCipher::create_or_throw("AES-256"));

      std::vector<uint8_t> keyAes(key, key + cipher->maximum_keylength());
      std::vector<uint8_t> block(ctr, ctr + cipher->block_size());


      cipher->set_key(keyAes);
      cipher->encrypt(block);

      std::copy(block.begin(), block.end(), buffer);
   }

   void AES256_CTR_DRBG_Update(unsigned char* provided_data, unsigned char* Key, unsigned char* V)
   {
      unsigned char   temp[48];

      for (int i = 0; i < 3; i++) {
         //increment V
         for (int j = 15; j >= 0; j--) {
            if (V[j] == 0xff)
               V[j] = 0x00;
            else {
               V[j]++;
               break;
            }
         }

         AES256_ECB(Key, V, temp + 16 * i);
      }
      if (provided_data != NULL)
         for (int i = 0; i < 48; i++)
            temp[i] ^= provided_data[i];
      memcpy(Key, temp, 32);
      memcpy(V, temp + 32, 16);
   }

      void clear() override
      {
         // reset struct
         memset(DRBG_ctx.Key, 0x00, 32);
         memset(DRBG_ctx.V, 0x00, 16);
         DRBG_ctx.reseed_counter = 0;
      }

      bool accepts_input() const override { return true; }

      void add_entropy(const uint8_t data[], size_t len) override
      {
         BOTAN_UNUSED(len);
         randombytes_init(data, nullptr, 256);
      }

      bool is_seeded() const override
      {
         return true;
      }

      void randomize(uint8_t out[], size_t len) override
      {
         randombytes(out, len);
      }

      Dilithium_Test_RNG(const std::vector<uint8_t>& seed)
      {
         clear();
         add_entropy(seed.data(), seed.size());
      }

   private:
      void randombytes_init(const unsigned char* entropy_input, unsigned char* personalization_string, int security_strength)
      {
         BOTAN_UNUSED(security_strength);
         unsigned char   seed_material[48];

         memcpy(seed_material, entropy_input, 48);
         if (personalization_string)
            for (int i = 0; i < 48; i++)
               seed_material[i] ^= personalization_string[i];
         memset(DRBG_ctx.Key, 0x00, 32);
         memset(DRBG_ctx.V, 0x00, 16);
         AES256_CTR_DRBG_Update(seed_material, DRBG_ctx.Key, DRBG_ctx.V);
         DRBG_ctx.reseed_counter = 1;
      }

      int randombytes(unsigned char* x, size_t xlen)
      {
         unsigned char   block[16];
         int             i = 0;

         while (xlen > 0) {
            //increment V
            for (int j = 15; j >= 0; j--) {
               if (DRBG_ctx.V[j] == 0xff)
                  DRBG_ctx.V[j] = 0x00;
               else {
                  DRBG_ctx.V[j]++;
                  break;
               }
            }
            AES256_ECB(DRBG_ctx.Key, DRBG_ctx.V, block);
            if (xlen > 15) {
               memcpy(x + i, block, 16);
               i += 16;
               xlen -= 16;
            }
            else {
               memcpy(x + i, block, xlen);
               xlen = 0;
            }
         }
         AES256_CTR_DRBG_Update(NULL, DRBG_ctx.Key, DRBG_ctx.V);
         DRBG_ctx.reseed_counter++;

         return 0;
      }

      typedef struct {
         unsigned char   Key[32];
         unsigned char   V[16];
         int             reseed_counter;
      } AES256_CTR_DRBG_struct;
      AES256_CTR_DRBG_struct  DRBG_ctx;
   };

}

template<typename DerivedT>
class Dilithium_KAT_Tests : public Text_Based_Test
   {
   public:
      Dilithium_KAT_Tests()
         : Text_Based_Test(DerivedT::test_vector, "count,seed,msg,pk_sha3_256,sk_sha3_256,sm") {}

      Test::Result run_one_test(const std::string &name, const VarMap &vars) override
         {
         Test::Result result(name);

         // read input from test file
         const auto ref_seed = vars.get_req_bin("seed");
         const auto ref_msg = vars.get_req_bin("msg");
         const auto ref_pk_hash = vars.get_req_bin("pk_sha3_256");
         const auto ref_sk_hash = vars.get_req_bin("sk_sha3_256");
         const auto ref_sm = vars.get_req_bin("sm");

         auto sha3_hasher = Botan::HashFunction::create_or_throw("SHA-3(256)");
         // Dilithium test RNG
         std::unique_ptr<Botan::RandomNumberGenerator>dilithium_test_rng;
         dilithium_test_rng.reset(new Dilithium_Test_RNG(ref_seed));

         Botan::Dilithium_PrivateKey priv_key(*dilithium_test_rng, DerivedT::mode);
         auto sk_hash = sha3_hasher->process(priv_key.private_key_bits());
         auto pk_hash = sha3_hasher->process(priv_key.public_key_bits());

         result.test_eq("Private key generation Botan style equal with reference: ",
            sk_hash, ref_sk_hash);
         result.test_eq("Public key generation Botan style equal with reference: ",
            pk_hash, ref_pk_hash);

         auto signer = Botan::PK_Signer(priv_key, *dilithium_test_rng, DerivedT::sign_param);
         auto signature = signer.sign_message(ref_msg.data(), ref_msg.size(), *dilithium_test_rng);
         result.test_eq("Signed Message Botan style equal with reference: ", signature,
            ref_sm);
         result.test_eq("Signed Message Length botan style equal with reference: ",
            signature.size(), ref_sm.size());

         Botan::Dilithium_PublicKey pub_key(priv_key.public_key_bits(), DerivedT::mode, Botan::DilithiumKeyEncoding::Raw);
         auto verificator = Botan::PK_Verifier(pub_key,"");
         verificator.update(ref_msg.data(), ref_msg.size());
         result.confirm("Signature Verification", verificator.check_signature(signature.data(), signature.size()));

         // wrong signagture
         auto mutated_signature = Test::mutate_vec(signature);
         result.confirm("Wrong Signature Verification", !verificator.check_signature(mutated_signature.data(), mutated_signature.size()));

         return result;
         }
   };

#define REGISTER_DILITHIUM_KAT_TEST(m, rand)                                       \
class DILITHIUM##m##rand final : public Dilithium_KAT_Tests<DILITHIUM##m##rand>    \
   {                                                                               \
   public:                                                                         \
      constexpr static auto test_vector = "pubkey/dilithium_" #m "_" #rand ".vec"; \
      constexpr static auto mode = Botan::DilithiumMode::Dilithium##m;             \
      constexpr static auto sign_param = #rand;                                    \
   };                                                                              \
   BOTAN_REGISTER_TEST("dilithium", "dilithium_kat_" #m "_" #rand, DILITHIUM##m##rand)

#if defined(BOTAN_HAS_DILITHIUM)
   REGISTER_DILITHIUM_KAT_TEST(4x4, Deterministic);
   REGISTER_DILITHIUM_KAT_TEST(6x5, Deterministic);
   REGISTER_DILITHIUM_KAT_TEST(8x7, Deterministic);
   REGISTER_DILITHIUM_KAT_TEST(4x4, Randomized);
   REGISTER_DILITHIUM_KAT_TEST(6x5, Randomized);
   REGISTER_DILITHIUM_KAT_TEST(8x7, Randomized);
#endif

#if defined(BOTAN_HAS_DILITHIUM_AES)
   REGISTER_DILITHIUM_KAT_TEST(4x4_AES, Deterministic);
   REGISTER_DILITHIUM_KAT_TEST(6x5_AES, Deterministic);
   REGISTER_DILITHIUM_KAT_TEST(8x7_AES, Deterministic);
   REGISTER_DILITHIUM_KAT_TEST(4x4_AES, Randomized);
   REGISTER_DILITHIUM_KAT_TEST(6x5_AES, Randomized);
   REGISTER_DILITHIUM_KAT_TEST(8x7_AES, Randomized);
#endif

class DilithiumRoundtripTests final : public Test
   {
   public:
      static Test::Result run_roundtrip(const char* test_name, Botan::DilithiumMode mode,
                                        bool randomized)
         {
         Test::Result result(test_name);

         auto sign = [randomized](const auto& private_key, const auto& msg)
            {
            const auto param = (randomized) ? "Randomized" : "Deterministic";
            auto signer = Botan::PK_Signer(private_key, Test::rng(), param);
            return signer.sign_message(msg, Test::rng());
            };

         auto verify = [](const auto& public_key, const auto& msg, const auto& signature)
            {
            auto verifier = Botan::PK_Verifier(public_key, "");
            verifier.update(msg);
            return verifier.check_signature(signature);
            };

         const std::string msg = "The quick brown fox jumps over the lazy dog.";
         const std::vector<uint8_t> msgvec(msg.data(), msg.data() + msg.size());

         Botan::Dilithium_PrivateKey priv_key(Test::rng(), mode);
         Botan::Dilithium_PublicKey pub_key = priv_key;

         const auto sig_before_codec = sign(priv_key, msgvec);
         std::vector<Botan::DilithiumKeyEncoding> encodings{Botan::DilithiumKeyEncoding::Raw, Botan::DilithiumKeyEncoding::DER};
         for(const auto encoding : encodings)
            {
            priv_key.set_binary_encoding(encoding);
            const auto priv_key_encoded = priv_key.private_key_bits();
            const auto pub_key_encoded = priv_key.public_key_bits();

            Botan::Dilithium_PrivateKey priv_key_decoded(priv_key_encoded, mode, encoding);
            Botan::Dilithium_PublicKey pub_key_decoded(pub_key_encoded, mode, encoding);

            const auto sig_after_codec = sign(priv_key_decoded, msgvec);

            result.confirm("Pubkey: before,   Sig: before", verify(pub_key, msgvec, sig_before_codec));
            result.confirm("Pubkey: before,   Sig: after", verify(pub_key, msgvec, sig_after_codec));
            result.confirm("Pubkey: after,    Sig: after", verify(pub_key_decoded, msgvec, sig_after_codec));
            result.confirm("Pubkey: after,    Sig: before", verify(pub_key_decoded, msgvec, sig_before_codec));
            result.confirm("Pubkey: recalc'ed Sig: before", verify(priv_key_decoded, msgvec, sig_before_codec));
            result.confirm("Pubkey: recalc'ed Sig: after", verify(priv_key_decoded, msgvec, sig_after_codec));

            auto tampered_msgvec = msgvec;
            tampered_msgvec.front() = 'X';
            result.confirm("Pubkey: before,   Broken Sig: before", !verify(pub_key, tampered_msgvec, sig_before_codec));
            result.confirm("Pubkey: before,   Broken Sig: after", !verify(pub_key, tampered_msgvec, sig_after_codec));
            result.confirm("Pubkey: after,    Broken Sig: after", !verify(pub_key_decoded, tampered_msgvec, sig_after_codec));
            result.confirm("Pubkey: after,    Broken Sig: before", !verify(pub_key_decoded, tampered_msgvec, sig_before_codec));
            result.confirm("Pubkey: recalc'ed Sig: before", !verify(priv_key_decoded, tampered_msgvec, sig_before_codec));
            result.confirm("Pubkey: recalc'ed Sig: after", !verify(priv_key_decoded, tampered_msgvec, sig_after_codec));
            }

         // decoding via generic pk_algs.h
         priv_key.set_binary_encoding(Botan::DilithiumKeyEncoding::Raw);
         const auto priv_key_encoded = priv_key.private_key_bits();
         const auto pub_key_encoded = priv_key.public_key_bits();

         const auto generic_pubkey_decoded = Botan::load_public_key(pub_key.algorithm_identifier(), pub_key_encoded);
         const auto generic_privkey_decoded = Botan::load_private_key(priv_key.algorithm_identifier(), priv_key_encoded);

         result.test_not_null("generic pubkey", generic_pubkey_decoded);
         result.test_not_null("generic privkey", generic_privkey_decoded);

         const auto sig_after_codec = sign(*generic_privkey_decoded, msgvec);

         result.confirm("verification with generic public key", verify(*generic_pubkey_decoded, msgvec, sig_before_codec));
         result.confirm("verification of signature with generic private key", verify(*generic_pubkey_decoded, msgvec, sig_after_codec));
         result.confirm("verification with generic private key", verify(*generic_privkey_decoded, msgvec, sig_before_codec));

         return result;
         }

   std::vector<Test::Result> run() override
      {
      std::vector<Test::Result> results;

#if defined(BOTAN_HAS_DILITHIUM)
      results.push_back(run_roundtrip("Dilithium_4x4_Common",
                                      Botan::DilithiumMode::Dilithium4x4, false));
      results.push_back(run_roundtrip("Dilithium_6x5_Common",
                                      Botan::DilithiumMode::Dilithium6x5, false));
      results.push_back(run_roundtrip("Dilithium_8x7_Common",
                                      Botan::DilithiumMode::Dilithium8x7, false));
      results.push_back(run_roundtrip("Dilithium_4x4_Common_Randomized",
                                      Botan::DilithiumMode::Dilithium4x4, true));
      results.push_back(run_roundtrip("Dilithium_6x5_Common_Randomized",
                                      Botan::DilithiumMode::Dilithium6x5, true));
      results.push_back(run_roundtrip("Dilithium_8x7_Common_Randomized",
                                      Botan::DilithiumMode::Dilithium8x7, true));
#endif

#if defined(BOTAN_HAS_DILITHIUM_AES)
      results.push_back(run_roundtrip("Dilithium_4x4_AES",
                                      Botan::DilithiumMode::Dilithium4x4_AES, false));
      results.push_back(run_roundtrip("Dilithium_6x5_AES",
                                      Botan::DilithiumMode::Dilithium6x5_AES, false));
      results.push_back(run_roundtrip("Dilithium_8x7_AES",
                                      Botan::DilithiumMode::Dilithium8x7_AES, false));
      results.push_back(run_roundtrip("Dilithium_4x4_AES_Randomized",
                                      Botan::DilithiumMode::Dilithium4x4_AES, true));
      results.push_back(run_roundtrip("Dilithium_6x5_AES_Randomized",
                                      Botan::DilithiumMode::Dilithium6x5_AES, true));
      results.push_back(run_roundtrip("Dilithium_8x7_AES_Randomized",
                                      Botan::DilithiumMode::Dilithium8x7_AES, true));
#endif

         return results;
      }
   };

BOTAN_REGISTER_TEST("dilithium", "dilithium_roundtrips", DilithiumRoundtripTests);

class Dilithium_Keygen_Tests final : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override
         {
         return
            {
#if defined(BOTAN_HAS_DILITHIUM_AES)
            "Dilithium-AES-r3/4x4",
            "Dilithium-AES-r3/6x5",
            "Dilithium-AES-r3/8x7",
#endif
#if defined(BOTAN_HAS_DILITHIUM)
            "Dilithium-r3/4x4",
            "Dilithium-r3/6x5",
            "Dilithium-r3/8x7",
#endif
            };
         }

      std::string algo_name() const override
         {
         return "Dilithium";
         }
   };

BOTAN_REGISTER_TEST("pubkey", "dilithium_keygen", Dilithium_Keygen_Tests);

#endif

} // namespace Botan_Tests
