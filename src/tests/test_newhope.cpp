/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_NEWHOPE) && defined(BOTAN_HAS_CHACHA)
  #include <botan/newhope.h>
  #include <botan/sha3.h>
  #include <botan/chacha.h>
  #include <botan/rng.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_NEWHOPE) && defined(BOTAN_HAS_CHACHA)

class NEWHOPE_RNG : public Botan::RandomNumberGenerator
   {
   public:
      std::string name() const override { return "NEWHOPE_RNG"; }
      void clear() override { /* ignored */ }

      void randomize(byte out[], size_t len) override
         {
         if(m_first.size() == len)
            {
            if(len != 32)
               throw Test_Error("NEWHOPE_RNG called in unexpected way, bad test?");

            Botan::copy_mem(out, m_first.data(), m_first.size());
            return;
            }

         /*
         * This slavishly emulates the behavior of the reference
         * implementations RNG, in order to ensure that from the same
         * random seed we compute the exact same result.
         */
         Botan::clear_mem(out, len);
         m_chacha.cipher1(out, len);

         m_calls += 1;

         byte nonce[8] = { 0 };

         if(m_calls < 3)
            {
            nonce[0] = m_calls;
            }
         else
            {
            nonce[7] = m_calls;
            }

         m_chacha.set_iv(nonce, 8);
         }

      bool is_seeded() const override { return true; }

      void add_entropy(const byte[], size_t) override { /* ignored */ }

      NEWHOPE_RNG(const std::vector<uint8_t>& seed)
         {
         if(seed.size() != 64 && seed.size() != 32)
            {
            throw Test_Error("Invalid NEWHOPE RNG seed");
            }

         if(seed.size() == 64)
            {
            m_first.assign(seed.begin(), seed.begin() + 32);
            m_chacha.set_key(seed.data() + 32, 32);
            }
         else
            {
            m_chacha.set_key(seed.data(), 32);
            }
         }

   private:
      Botan::ChaCha m_chacha;
      std::vector<uint8_t> m_first;
      byte m_calls = 0;
   };

class NEWHOPE_Tests : public Text_Based_Test
   {
   public:
      NEWHOPE_Tests() : Text_Based_Test("pubkey/newhope.vec", {"DRBG_SeedA", "H_OutputA", "DRBG_SeedB", "H_OutputB", "SharedKey"}) {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("NEWHOPE");

         const std::vector<uint8_t> h_output_a = get_req_bin(vars, "H_OutputA");
         const std::vector<uint8_t> h_output_b = get_req_bin(vars, "H_OutputB");
         const std::vector<uint8_t> shared_key = get_req_bin(vars, "SharedKey");

         NEWHOPE_RNG drbg_a(get_req_bin(vars, "DRBG_SeedA"));
         NEWHOPE_RNG drbg_b(get_req_bin(vars, "DRBG_SeedB"));

         Botan::SHA_3_256 sha3;

         std::vector<uint8_t> send_a(NEWHOPE_SENDABYTES);
         Botan::newhope_poly a_sk;
         Botan::newhope_keygen(send_a.data(), &a_sk, drbg_a);

         std::vector<uint8_t> h_send_a(sha3.output_length());
         sha3.update(send_a);
         sha3.final(h_send_a.data());
         result.test_eq("Hash Output A", h_send_a, h_output_a);

         std::vector<uint8_t> sharedkey_b(32);
         std::vector<uint8_t> send_b(NEWHOPE_SENDBBYTES);
         Botan::newhope_sharedb(sharedkey_b.data(), send_b.data(), send_a.data(), drbg_b);
         result.test_eq("Key B", sharedkey_b, shared_key);

         std::vector<uint8_t> h_send_b(sha3.output_length());
         sha3.update(send_b);
         sha3.final(h_send_b.data());
         result.test_eq("Hash Output B", h_send_b, h_output_b);

         std::vector<uint8_t> sharedkey_a(32);
         newhope_shareda(sharedkey_a.data(), &a_sk, send_b.data());
         result.test_eq("Key A", sharedkey_a, shared_key);

         return result;
         }
   };

BOTAN_REGISTER_TEST("newhope", NEWHOPE_Tests);

#endif

}
