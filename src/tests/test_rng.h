/*
* (C) 2009 Jack Lloyd
* (C) 2016 René Korthaus, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TESTS_FIXED_RNG_H_
#define BOTAN_TESTS_FIXED_RNG_H_

#include "tests.h"
#include <deque>
#include <string>
#include <botan/rng.h>
#include <botan/hex.h>
#include <botan/exceptn.h>

namespace Botan_Tests {

/**
 * RNG that outputs only a given set of fixed bytes, throws otherwise.
 * Useful for test vectors with fixed nonces, where the algorithm consumes only the fixed nonce.
 */
class Fixed_Output_RNG : public Botan::RandomNumberGenerator
   {
   public:
      bool is_seeded() const override
         {
         return !m_buf.empty();
         }

      bool accepts_input() const override { return true; }

      size_t reseed(Botan::Entropy_Sources&,
                    size_t,
                    std::chrono::milliseconds) override
         {
         return 0;
         }

      void randomize(uint8_t out[], size_t len) override
         {
         for(size_t j = 0; j != len; j++)
            {
            out[j] = random();
            }
         }

      void add_entropy(const uint8_t b[], size_t s) override
         {
         m_buf.insert(m_buf.end(), b, b + s);
         }

      std::string name() const override
         {
         return "Fixed_Output_RNG";
         }

      void clear() noexcept override {}

      explicit Fixed_Output_RNG(const std::vector<uint8_t>& in)
         {
         m_buf.insert(m_buf.end(), in.begin(), in.end());
         }

      explicit Fixed_Output_RNG(const std::string& in_str)
         {
         std::vector<uint8_t> in = Botan::hex_decode(in_str);
         m_buf.insert(m_buf.end(), in.begin(), in.end());
         }

      Fixed_Output_RNG(RandomNumberGenerator& rng, size_t len)
         {
         std::vector<uint8_t> output;
         rng.random_vec(output, len);
         m_buf.insert(m_buf.end(), output.begin(), output.end());
         }

      Fixed_Output_RNG() = default;
   protected:
      uint8_t random()
         {
         if(m_buf.empty())
            {
            throw Test_Error("Fixed output RNG ran out of bytes, test bug?");
            }

         uint8_t out = m_buf.front();
         m_buf.pop_front();
         return out;
         }

   private:
      std::deque<uint8_t> m_buf;
   };

/**
 * RNG that outputs a given set of fixed bytes for a specific request count, outputs random otherwise.
 * Useful for test vectors with fixed nonces, where the algorithm consumes more random than just the fixed nonce.
 */
class Fixed_Output_Position_RNG final : public Fixed_Output_RNG
   {
   public:
      bool is_seeded() const override
         {
         return Fixed_Output_RNG::is_seeded() || Test::rng().is_seeded();
         }

      void randomize(uint8_t out[], size_t len) override
         {
         ++m_requests;

         if(m_requests == m_pos)
            {
            // return fixed output
            for(size_t j = 0; j != len; j++)
               {
               out[j] = random();
               }
            }
         else
            {
            // return random
            Test::rng().randomize(out, len);
            }
         }

      bool accepts_input() const override { return false; }

      void add_entropy(const uint8_t*, size_t) override
         {
         throw Test_Error("add_entropy() not supported by this RNG, test bug?");
         }

      std::string name() const override
         {
         return "Fixed_Output_Position_RNG";
         }

      explicit Fixed_Output_Position_RNG(const std::vector<uint8_t>& in, size_t pos)
         : Fixed_Output_RNG(in)
         , m_pos(pos) {}

      explicit Fixed_Output_Position_RNG(const std::string& in_str, size_t pos)
         : Fixed_Output_RNG(in_str)
         , m_pos(pos) {}

   private:
      size_t m_pos = 0;
      size_t m_requests = 0;
   };

class SeedCapturing_RNG final : public Botan::RandomNumberGenerator
   {
   public:
      void randomize(uint8_t[], size_t) override
         {
         throw Test_Error("SeedCapturing_RNG has no output");
         }

      bool accepts_input() const override { return true; }

      void add_entropy(const uint8_t input[], size_t len) override
         {
         m_samples++;
         m_seed.insert(m_seed.end(), input, input + len);
         }

      void clear() override {}
      bool is_seeded() const override
         {
         return false;
         }
      std::string name() const override
         {
         return "SeedCapturing";
         }

      size_t samples() const
         {
         return m_samples;
         }

      const std::vector<uint8_t>& seed_material() const
         {
         return m_seed;
         }

   private:
      std::vector<uint8_t> m_seed;
      size_t m_samples = 0;
   };

/*
* RNG that counts the number of requests made to it, for example
* to verify that a reseed attempt was made at the expected time.
*/
class Request_Counting_RNG final : public Botan::RandomNumberGenerator
   {
   public:
      Request_Counting_RNG() : m_randomize_count(0) {}

      size_t randomize_count() const
         {
         return m_randomize_count;
         }

      bool accepts_input() const override { return false; }

      bool is_seeded() const override
         {
         return true;
         }

      void clear() override
         {
         m_randomize_count = 0;
         }

      void randomize(uint8_t out[], size_t out_len) override
         {
         /*
         The HMAC_DRBG and ChaCha reseed KATs assume this RNG type
         outputs all 0x80
         */
         for(size_t i = 0; i != out_len; ++i)
            out[i] = 0x80;
         m_randomize_count++;
         }

      void add_entropy(const uint8_t[], size_t) override {}

      std::string name() const override
         {
         return "Request_Counting_RNG";
         }

   private:
      size_t m_randomize_count;
   };

}

#endif
