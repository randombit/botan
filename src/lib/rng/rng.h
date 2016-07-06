/*
* Random Number Generator base classes
* (C) 1999-2009,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_RANDOM_NUMBER_GENERATOR_H__
#define BOTAN_RANDOM_NUMBER_GENERATOR_H__

#include <botan/secmem.h>
#include <botan/exceptn.h>
#include <chrono>
#include <string>
#include <mutex>

namespace Botan {

class Entropy_Sources;

/**
* An interface to a generic RNG
*/
class BOTAN_DLL RandomNumberGenerator
   {
   public:
      virtual ~RandomNumberGenerator() = default;

      RandomNumberGenerator() = default;

      /*
      * Never copy a RNG, create a new one
      */
      RandomNumberGenerator(const RandomNumberGenerator& rng) = delete;
      RandomNumberGenerator& operator=(const RandomNumberGenerator& rng) = delete;

      /**
      * Randomize a byte array.
      * @param output the byte array to hold the random output.
      * @param length the length of the byte array output.
      */
      virtual void randomize(byte output[], size_t length) = 0;

      /**
      * Incorporate some additional data into the RNG state. For
      * example adding nonces or timestamps from a peer's protocol
      * message can help hedge against VM state rollback attacks.
      *
      * @param inputs a byte array containg the entropy to be added
      * @param length the length of the byte array in
      */
      virtual void add_entropy(const byte input[], size_t length) = 0;

      /**
      * Incorporate some additional data into the RNG state.
      */
      template<typename T> void add_entropy_T(const T& t)
         {
         add_entropy(reinterpret_cast<const uint8_t*>(&t), sizeof(T));
         }

      /**
      * Incorporate entropy into the RNG state then produce output
      * Some RNG types implement this using a single operation.
      */
      virtual void randomize_with_input(byte output[], size_t output_len,
                                        const byte input[], size_t input_len)
         {
         this->add_entropy(input, input_len);
         this->randomize(output, output_len);
         }

      /**
      * Return the name of this object
      */
      virtual std::string name() const = 0;

      /**
      * Clear all internally held values of this RNG.
      */
      virtual void clear() = 0;

      /**
      * Check whether this RNG is seeded.
      * @return true if this RNG was already seeded, false otherwise.
      */
      virtual bool is_seeded() const = 0;

      /**
      * Poll provided sources for up to poll_bits bits of entropy
      * or until the timeout expires. Returns estimate of the number
      * of bits collected.
      */
      virtual size_t reseed_with_sources(Entropy_Sources& srcs,
                                         size_t poll_bits,
                                         std::chrono::milliseconds poll_timeout);

      /**
      * Reseed this RNG from the default entropy sources and a default timeout
      * @param bits_to_collect is the number of bits of entropy to
      *        attempt to gather from the entropy sources
      * @param poll_timeout try not to run longer than this, even if
      *        not enough entropy has been collected
      */
      size_t reseed(size_t bits_to_collect = BOTAN_RNG_RESEED_POLL_BITS);

      /**
      * Reseed this RNG from the default entropy sources
      * @param bits_to_collect is the number of bits of entropy to
      *        attempt to gather from the entropy sources
      * @param poll_timeout try not to run longer than this, even if
      *        not enough entropy has been collected
      */
      size_t reseed_with_timeout(size_t bits_to_collect,
                                 std::chrono::milliseconds poll_timeout);

      /**
      * Return a random vector
      * @param bytes number of bytes in the result
      * @return randomized vector of length bytes
      */
      secure_vector<byte> random_vec(size_t bytes)
         {
         secure_vector<byte> output(bytes);
         randomize(output.data(), output.size());
         return output;
         }

      /**
      * Return a random byte
      * @return random byte
      */
      byte next_byte()
         {
         byte b;
         this->randomize(&b, 1);
         return b;
         }

      byte next_nonzero_byte()
         {
         byte b = next_byte();
         while(b == 0)
            b = next_byte();
         return b;
         }

      /**
      * Create a seeded and active RNG object for general application use
      * Added in 1.8.0
      * Use AutoSeeded_RNG instead
      */
      static RandomNumberGenerator* make_rng();
   };

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
      Stateful_RNG(size_t max_output_before_reseed);

      virtual bool is_seeded() const override final;

      /**
      * Consume this input and mark the RNG as initialized regardless
      * of the length of the input or the current seeded state of
      * the RNG.
      */
      void initialize_with(const byte input[], size_t length);

      /**
      * Poll provided sources for up to poll_bits bits of entropy
      * or until the timeout expires. Returns estimate of the number
      * of bits collected.
      */
      size_t reseed_with_sources(Entropy_Sources& srcs,
                                 size_t poll_bits,
                                 std::chrono::milliseconds poll_timeout) override;

   protected:
      void reseed_check(size_t bytes_requested);

      void clear() override;

      /**
      * Mark state as requiring a reseed on next use
      */
      void force_reseed() { m_bytes_since_reseed = m_max_output_before_reseed; }

      uint32_t last_pid() const { return m_last_pid; }

      mutable std::mutex m_mutex;

   private:
      const size_t m_max_output_before_reseed;
      size_t m_bytes_since_reseed = 0;
      uint32_t m_last_pid = 0;
      bool m_successful_initialization = false;
   };

/**
* Convenience typedef
*/
typedef RandomNumberGenerator RNG;

/**
* Hardware RNG has no members but exists to tag hardware RNG types
*/
class BOTAN_DLL Hardware_RNG : public RandomNumberGenerator
   {
   };

/**
* Null/stub RNG - fails if you try to use it for anything
* This is not generally useful except for in certain tests
*/
class BOTAN_DLL Null_RNG final : public RandomNumberGenerator
   {
   public:
      bool is_seeded() const override { return false; }

      void clear() override {}

      void randomize(byte[], size_t) override
         {
         throw Exception("Null_RNG called");
         }

      void add_entropy(const byte[], size_t) override {}

      std::string name() const override { return "Null_RNG"; }
   };

/**
* Wraps access to a RNG in a mutex
*/
class BOTAN_DLL Serialized_RNG final : public RandomNumberGenerator
   {
   public:
      void randomize(byte out[], size_t len) override
         {
         std::lock_guard<std::mutex> lock(m_mutex);
         m_rng->randomize(out, len);
         }

      bool is_seeded() const override
         {
         std::lock_guard<std::mutex> lock(m_mutex);
         return m_rng->is_seeded();
         }

      void clear() override
         {
         std::lock_guard<std::mutex> lock(m_mutex);
         m_rng->clear();
         }

      std::string name() const override
         {
         std::lock_guard<std::mutex> lock(m_mutex);
         return m_rng->name();
         }

      size_t reseed_with_sources(Entropy_Sources& src,
                                 size_t bits,
                                 std::chrono::milliseconds msec) override
         {
         std::lock_guard<std::mutex> lock(m_mutex);
         return m_rng->reseed_with_sources(src, bits, msec);
         }

      void add_entropy(const byte in[], size_t len) override
         {
         std::lock_guard<std::mutex> lock(m_mutex);
         m_rng->add_entropy(in, len);
         }

      Serialized_RNG() : m_rng(RandomNumberGenerator::make_rng()) {}
      explicit Serialized_RNG(RandomNumberGenerator* rng) : m_rng(rng) {}
   private:
      mutable std::mutex m_mutex;
      std::unique_ptr<RandomNumberGenerator> m_rng;
   };

}

#endif
