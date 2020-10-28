/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_NEWHOPE) && defined(BOTAN_HAS_CHACHA)
   #include <botan/newhope.h>
   #include <botan/hash.h>
   #include <botan/stream_cipher.h>
   #include <botan/rng.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_NEWHOPE) && defined(BOTAN_HAS_CHACHA)

class NEWHOPE_RNG final : public Botan::RandomNumberGenerator
   {
   public:
      std::string name() const override
         {
         return "NEWHOPE_RNG";
         }
      void clear() override
         {
         /* ignored */
         }

      void randomize(uint8_t out[], size_t len) override
         {
         if(m_first.size() == len)
            {
            if(len != 32)
               {
               throw Test_Error("NEWHOPE_RNG called in unexpected way, bad test?");
               }

            Botan::copy_mem(out, m_first.data(), m_first.size());
            return;
            }

         /*
         * This slavishly emulates the behavior of the reference
         * implementations RNG, in order to ensure that from the same
         * random seed we compute the exact same result.
         */
         Botan::clear_mem(out, len);
         m_chacha->cipher1(out, len);

         m_calls += 1;

         uint8_t nonce[8] = { 0 };

         if(m_calls < 3)
            {
            nonce[0] = m_calls;
            }
         else
            {
            nonce[7] = m_calls;
            }

         m_chacha->set_iv(nonce, 8);
         }

      bool is_seeded() const override
         {
         return true;
         }

      bool accepts_input() const override { return false; }

      void add_entropy(const uint8_t[], size_t) override
         {
         /* ignored */
         }

      NEWHOPE_RNG(const std::vector<uint8_t>& seed)
         {
         m_chacha = Botan::StreamCipher::create_or_throw("ChaCha20");

         if(seed.size() != 64 && seed.size() != 32)
            {
            throw Test_Error("Invalid NEWHOPE RNG seed");
            }

         if(seed.size() == 64)
            {
            m_first.assign(seed.begin(), seed.begin() + 32);
            m_chacha->set_key(seed.data() + 32, 32);
            }
         else
            {
            m_chacha->set_key(seed.data(), 32);
            }
         }

   private:
      std::unique_ptr<Botan::StreamCipher> m_chacha;
      std::vector<uint8_t> m_first;
      uint8_t m_calls = 0;
   };

class NEWHOPE_Tests final : public Text_Based_Test
   {
   public:
      NEWHOPE_Tests()
         : Text_Based_Test(
              "pubkey/newhope.vec",
              "DRBG_SeedA,H_OutputA,DRBG_SeedB,H_OutputB,SharedKey") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("NEWHOPE");

         const std::vector<uint8_t> h_output_a = vars.get_req_bin("H_OutputA");
         const std::vector<uint8_t> h_output_b = vars.get_req_bin("H_OutputB");
         const std::vector<uint8_t> shared_key = vars.get_req_bin("SharedKey");

         NEWHOPE_RNG drbg_a(vars.get_req_bin("DRBG_SeedA"));
         NEWHOPE_RNG drbg_b(vars.get_req_bin("DRBG_SeedB"));

         std::unique_ptr<Botan::HashFunction> sha3 = Botan::HashFunction::create("SHA-3(256)");

         std::vector<uint8_t> send_a(Botan::NEWHOPE_SENDABYTES);
         Botan::newhope_poly a_sk;
         Botan::newhope_keygen(send_a.data(), &a_sk, drbg_a);

         std::vector<uint8_t> h_send_a(sha3->output_length());
         sha3->update(send_a);
         sha3->final(h_send_a.data());
         result.test_eq("Hash Output A", h_send_a, h_output_a);

         std::vector<uint8_t> sharedkey_b(32);
         std::vector<uint8_t> send_b(Botan::NEWHOPE_SENDBBYTES);
         Botan::newhope_sharedb(sharedkey_b.data(), send_b.data(), send_a.data(), drbg_b);
         result.test_eq("Key B", sharedkey_b, shared_key);

         std::vector<uint8_t> h_send_b(sha3->output_length());
         sha3->update(send_b);
         sha3->final(h_send_b.data());
         result.test_eq("Hash Output B", h_send_b, h_output_b);

         std::vector<uint8_t> sharedkey_a(32);
         newhope_shareda(sharedkey_a.data(), &a_sk, send_b.data());
         result.test_eq("Key A", sharedkey_a, shared_key);

         return result;
         }
   };

BOTAN_REGISTER_TEST("pubkey", "newhope", NEWHOPE_Tests);

#endif

}
