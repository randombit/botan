/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_STATEFUL_RNG_H_
#define BOTAN_STATEFUL_RNG_H_

#include <botan/mutex.h>
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
class BOTAN_PUBLIC_API(2, 0) Stateful_RNG : public RandomNumberGenerator {
   public:
      /**
      * Create a Stateful_RNG which reseeds from both an RNG and entropy sources
      *
      * @param rng is a reference to some RNG which will be used
      * to perform the periodic reseeding
      * @param entropy_sources will be polled to perform reseeding periodically
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed
      */
      Stateful_RNG(RandomNumberGenerator& rng, Entropy_Sources& entropy_sources, size_t reseed_interval) :
            m_underlying_rng(&rng), m_entropy_sources(&entropy_sources), m_reseed_interval(reseed_interval) {}

      /**
      * Create a Stateful_RNG which reseeds from another RNG
      *
      * @param rng is a reference to some RNG which will be used
      * to perform the periodic reseeding
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed
      */
      Stateful_RNG(RandomNumberGenerator& rng, size_t reseed_interval) :
            m_underlying_rng(&rng), m_reseed_interval(reseed_interval) {}

      /**
      * Create a Stateful_RNG which reseeds from entropy sources
      *
      * @param entropy_sources will be polled to perform reseeding periodically
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed
      */
      Stateful_RNG(Entropy_Sources& entropy_sources, size_t reseed_interval) :
            m_entropy_sources(&entropy_sources), m_reseed_interval(reseed_interval) {}

      /**
      * In this case, automatic reseeding is impossible
      */
      Stateful_RNG() : m_reseed_interval(0) {}

      /**
      * Consume this input and mark the RNG as initialized regardless
      * of the length of the input or the current seeded state of
      * the RNG.
      */
      void initialize_with(std::span<const uint8_t> input);

      /**
      * Consume this input and mark the RNG as initialized regardless
      * of the length of the input or the current seeded state of the RNG.
      * @param input the seed material
      * @param length the number of bytes in input
      */
      void initialize_with(const uint8_t input[], size_t length) { this->initialize_with(std::span(input, length)); }

      /**
      * Test whether this RNG has been seeded
      * @return true if this RNG is seeded and ready for use
      */
      bool is_seeded() const final;

      /**
      * Test whether this RNG accepts externally provided input
      * @return false if this RNG is known to ignore provided inputs
      */
      bool accepts_input() const final { return true; }

      /**
      * Mark state as requiring a reseed on next use
      */
      void force_reseed();

      /**
      * Reseed this RNG from another RNG
      * @param rng the RNG to draw seed material from
      * @param poll_bits the number of bits to collect
      */
      void reseed_from_rng(RandomNumberGenerator& rng, size_t poll_bits = RandomNumberGenerator::DefaultPollBits) final;

      /**
      * Poll provided sources for up to poll_bits bits of entropy.
      * Returns estimate of the number of bits collected.
      */
      size_t reseed_from_sources(Entropy_Sources& srcs,
                                 size_t poll_bits = RandomNumberGenerator::DefaultPollBits) final;

      /**
      * Return the security level of this DRBG
      * @return intended security level of this DRBG
      */
      virtual size_t security_level() const = 0;

      /**
      * Return the largest number of bytes this DRBG will produce per request
      * Some DRBGs have a notion of the maximum number of bytes per
      * request.  Longer requests (to randomize) will be treated as
      * multiple requests, and may initiate reseeding multiple times,
      * depending on the values of max_number_of_bytes_per_request and
      * reseed_interval(). This function returns zero if the RNG in
      * question does not have such a notion.
      *
      * @return max number of bytes per request (or zero)
      */
      virtual size_t max_number_of_bytes_per_request() const = 0;

      /**
      * Return how many requests may be made before automatic reseeding
      * @return the reseed interval, or zero if automatic reseeding is disabled
      */
      size_t reseed_interval() const { return m_reseed_interval; }

      /**
      * Clear all internally held values of this RNG
      */
      void clear() final;

   protected:
      /**
      * Reseed if the reseed interval has elapsed, or throw if unseeded
      */
      void reseed_check();

      /**
      * Generate output, incorporating the provided input
      * @param output the buffer to fill
      * @param input additional input to incorporate
      */
      virtual void generate_output(std::span<uint8_t> output, std::span<const uint8_t> input) = 0;

      /**
      * Incorporate the provided input into the RNG state
      * @param input the seed material
      */
      virtual void update(std::span<const uint8_t> input) = 0;

      /**
      * Clear the subclass specific portion of the RNG state
      */
      virtual void clear_state() = 0;

   private:
      void generate_batched_output(std::span<uint8_t> output, std::span<const uint8_t> input);

      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) final;

      void reset_reseed_counter();

      mutable recursive_mutex_type m_mutex;

      // A non-owned and possibly null pointer to shared RNG
      RandomNumberGenerator* m_underlying_rng = nullptr;

      // A non-owned and possibly null pointer to a shared Entropy_Source
      Entropy_Sources* m_entropy_sources = nullptr;

      const size_t m_reseed_interval;
      uint32_t m_last_pid = 0;

      /*
      * Set to 1 after a successful seeding, then incremented.  Reset
      * to 0 by clear() or a fork. This logic is used even if
      * automatic reseeding is disabled (via m_reseed_interval = 0)
      */
      size_t m_reseed_counter = 0;
};

}  // namespace Botan

#endif
