/*
* (C) 2009,2023 Jack Lloyd
* (C) 2016 René Korthaus, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TESTS_RNGS_FOR_TESTING_H_
#define BOTAN_TESTS_RNGS_FOR_TESTING_H_

#include "tests.h"
#include <botan/exceptn.h>
#include <botan/hex.h>
#include <botan/rng.h>
#include <deque>
#include <string>

#if defined(BOTAN_HAS_AES)
   #include <botan/block_cipher.h>
#endif

namespace Botan_Tests {

/**
 * RNG that outputs only a given set of fixed bytes, throws otherwise.
 * Useful for test vectors with fixed nonces, where the algorithm consumes only the fixed nonce.
 */
class Fixed_Output_RNG : public Botan::RandomNumberGenerator {
   public:
      bool empty() const { return !is_seeded(); }

      bool is_seeded() const override { return !m_buf.empty(); }

      bool accepts_input() const override { return true; }

      size_t reseed(Botan::Entropy_Sources&, size_t, std::chrono::milliseconds) override { return 0; }

      std::string name() const override { return "Fixed_Output_RNG"; }

      void clear() noexcept override {}

      explicit Fixed_Output_RNG(std::span<const uint8_t> in) { m_buf.insert(m_buf.end(), in.begin(), in.end()); }

      explicit Fixed_Output_RNG(const std::string& in_str) {
         std::vector<uint8_t> in = Botan::hex_decode(in_str);
         m_buf.insert(m_buf.end(), in.begin(), in.end());
      }

      Fixed_Output_RNG(RandomNumberGenerator& rng, size_t len) {
         std::vector<uint8_t> output;
         rng.random_vec(output, len);
         m_buf.insert(m_buf.end(), output.begin(), output.end());
      }

      /**
       * Provide a non-fixed RNG as fallback to be used once the Fixed_Output_RNG runs out of bytes.
       * If more bytes are provided after that, those will be preferred over the fallback again.
       */
      Fixed_Output_RNG(RandomNumberGenerator& fallback_rng) : m_fallback(&fallback_rng) {}

      Fixed_Output_RNG() = default;

   protected:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) override {
         m_buf.insert(m_buf.end(), input.begin(), input.end());

         for(auto& o : output) {
            o = random();
         }
      }

      uint8_t random() {
         if(m_buf.empty()) {
            if(m_fallback.has_value()) {
               return m_fallback.value()->next_byte();
            } else {
               throw Test_Error("Fixed output RNG ran out of bytes, test bug?");
            }
         }

         uint8_t out = m_buf.front();
         m_buf.pop_front();
         return out;
      }

   private:
      std::deque<uint8_t> m_buf;
      std::optional<RandomNumberGenerator*> m_fallback;
};

/**
 * RNG that outputs a given set of fixed bytes for a specific request count, outputs random otherwise.
 * Useful for test vectors with fixed nonces, where the algorithm consumes more random than just the fixed nonce.
 */
class Fixed_Output_Position_RNG final : public Fixed_Output_RNG {
   public:
      // We output either the fixed output, or otherwise random
      bool is_seeded() const override { return true; }

      bool accepts_input() const override { return false; }

      std::string name() const override { return "Fixed_Output_Position_RNG"; }

      Fixed_Output_Position_RNG(const std::vector<uint8_t>& in, size_t pos, Botan::RandomNumberGenerator& rng) :
            Fixed_Output_RNG(in), m_pos(pos), m_rng(rng) {}

      Fixed_Output_Position_RNG(const std::string& in_str, size_t pos, Botan::RandomNumberGenerator& rng) :
            Fixed_Output_RNG(in_str), m_pos(pos), m_rng(rng) {}

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) override {
         if(!input.empty()) {
            throw Test_Error("add_entropy() not supported by this RNG, test bug?");
         }

         ++m_requests;

         if(m_requests == m_pos) {
            // return fixed output
            Fixed_Output_RNG::fill_bytes_with_input(output, input);
         } else {
            // return random
            m_rng.random_vec(output);
         }
      }

   private:
      size_t m_pos = 0;
      size_t m_requests = 0;
      Botan::RandomNumberGenerator& m_rng;
};

class SeedCapturing_RNG final : public Botan::RandomNumberGenerator {
   public:
      bool accepts_input() const override { return true; }

      void clear() override {}

      bool is_seeded() const override { return false; }

      std::string name() const override { return "SeedCapturing"; }

      size_t samples() const { return m_samples; }

      const std::vector<uint8_t>& seed_material() const { return m_seed; }

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) override {
         if(!output.empty()) {
            throw Test_Error("SeedCapturing_RNG has no output");
         }

         m_samples++;
         m_seed.insert(m_seed.end(), input.begin(), input.end());
      }

   private:
      std::vector<uint8_t> m_seed;
      size_t m_samples = 0;
};

/*
* RNG that counts the number of requests made to it, for example
* to verify that a reseed attempt was made at the expected time.
*/
class Request_Counting_RNG final : public Botan::RandomNumberGenerator {
   public:
      Request_Counting_RNG() : m_randomize_count(0) {}

      size_t randomize_count() const { return m_randomize_count; }

      bool accepts_input() const override { return false; }

      bool is_seeded() const override { return true; }

      void clear() override { m_randomize_count = 0; }

      std::string name() const override { return "Request_Counting_RNG"; }

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> /* ignored */) override {
         /*
         The HMAC_DRBG and ChaCha reseed KATs assume this RNG type
         outputs all 0x80
         */
         for(auto& out : output) {
            out = 0x80;
         }
         if(!output.empty()) {
            m_randomize_count++;
         }
      }

   private:
      size_t m_randomize_count;
};

#if defined(BOTAN_HAS_AES)

// A number of PQC algorithms use CTR_DRBG with AES-256 as a source
// of randomness for their test vectors. This is not a complete
// CTR_DRBG implementation, but is sufficient for running such tests
class CTR_DRBG_AES256 final : public Botan::RandomNumberGenerator {
   public:
      std::string name() const override { return "CTR_DRBG(AES-256)"; }

      void clear() override;

      bool accepts_input() const override { return true; }

      bool is_seeded() const override { return true; }

      CTR_DRBG_AES256(std::span<const uint8_t> seed);

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) override;

      void incr_V_into(std::span<uint8_t> output);

      void update(std::span<const uint8_t> provided_data);

      uint64_t m_V0, m_V1;
      std::unique_ptr<Botan::BlockCipher> m_cipher;
};

#endif

}  // namespace Botan_Tests

#endif
