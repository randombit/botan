/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_STATEFUL_RNG_H__
#define BOTAN_STATEFUL_RNG_H__

#include <botan/rng.h>

namespace Botan {

/**
* Inherited by RNGs which maintain in-process state, like HMAC_DRBG.
* On Unix these RNGs are vulnerable to problems with fork, where the
* RNG state is duplicated, and the parent and child process RNGs will
* produce identical output until one of them reseeds. Stateful_RNG
* reseeds itself whenever a fork is detected, or after a set number of
* bytes have been output.
*
* Not implemented by RNGs which access an external RNG, such as the
* system PRNG or a hardware RNG.
*/
class BOTAN_DLL Stateful_RNG : public RandomNumberGenerator
   {
   public:
      Stateful_RNG(RandomNumberGenerator& rng,
                   Entropy_Sources& entropy_sources,
                   size_t max_output_before_reseed) :
         m_underlying_rng(&rng),
         m_entropy_sources(&entropy_sources),
         m_max_output_before_reseed(max_output_before_reseed)
         {}

      Stateful_RNG(RandomNumberGenerator& rng, size_t max_output_before_reseed) :
         m_underlying_rng(&rng),
         m_max_output_before_reseed(max_output_before_reseed)
         {}

      Stateful_RNG(Entropy_Sources& entropy_sources, size_t max_output_before_reseed) :
         m_entropy_sources(&entropy_sources),
         m_max_output_before_reseed(max_output_before_reseed)
         {}

      /**
      * In this case, reseeding is impossible
      */
      Stateful_RNG() : m_max_output_before_reseed(0) {}

      /**
      * Consume this input and mark the RNG as initialized regardless
      * of the length of the input or the current seeded state of
      * the RNG.
      */
      void initialize_with(const byte input[], size_t length);

      bool is_seeded() const override final;

      void reseed_from_rng(RandomNumberGenerator& rng,
                           size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS) override final;

      /**
      * Poll provided sources for up to poll_bits bits of entropy
      * or until the timeout expires. Returns estimate of the number
      * of bits collected.
      */
      size_t reseed(Entropy_Sources& srcs,
                    size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS,
                    std::chrono::milliseconds poll_timeout = BOTAN_RNG_RESEED_DEFAULT_TIMEOUT) override;

      virtual size_t security_level() const = 0;

   protected:
      /**
      * Called with lock held
      */
      void reseed_check(size_t bytes_requested);

      void clear() override;

      /**
      * Mark state as requiring a reseed on next use
      */
      void force_reseed() { m_bytes_since_reseed = m_max_output_before_reseed; }

      uint32_t last_pid() const { return m_last_pid; }

   private:
      // A non-owned and possibly null pointer to shared RNG
      RandomNumberGenerator* m_underlying_rng = nullptr;

      // A non-owned and possibly null pointer to a shared Entropy_Source
      Entropy_Sources* m_entropy_sources = nullptr;

      const size_t m_max_output_before_reseed;
      size_t m_bytes_since_reseed = 0;
      uint32_t m_last_pid = 0;
      bool m_successful_initialization = false;
   };

}

#endif
