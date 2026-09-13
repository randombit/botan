/*
* Random Number Generator base classes
* (C) 1999-2009,2015,2016 Jack Lloyd
*     2023                René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_RANDOM_NUMBER_GENERATOR_H_
#define BOTAN_RANDOM_NUMBER_GENERATOR_H_

#include <botan/concepts.h>
#include <botan/secmem.h>

#include <array>
#include <concepts>
#include <span>
#include <string>
#include <type_traits>

/*
* We only include <chrono> in downstream applications to avoid
* breaking semver wrt RandomNumberGenerator::reseed. Within the
* library we avoid it because it slows down compilation significantly.
*
* TODO(Botan4): remove this entirely
*/
#if !defined(BOTAN_IS_BEING_BUILT)
   #include <chrono>
#endif

namespace Botan {

class Entropy_Sources;

/**
* Estimate of the amount of entropy contained in an input passed to
* RandomNumberGenerator::add_entropy
*
* Stateful RNGs such as HMAC_DRBG use this estimate to decide whether the
* provided input is sufficient to consider the RNG as seeded. RNGs which do
* not track a seeded state ignore the estimate.
*/
class BOTAN_PUBLIC_API(3, 14) Entropy_Estimate final {
   public:
      /**
      * Specifies that the input is assumed to contain full entropy, ie as
      * many bits of entropy as it has bits. This is the default used by
      * add_entropy.
      */
      class Full final {};

      /**
      * A number of bits of entropy
      *
      * Entropy_Estimate is constructed from this type rather than from a
      * plain integer so that the unit is explicit at the call site, eg
      * Entropy_Estimate::Bits(128).
      */
      class Bits final {
         public:
            constexpr explicit Bits(size_t bits) : m_bits(bits) {}

            constexpr size_t value() const { return m_bits; }

         private:
            size_t m_bits;
      };

      /**
      * The input is assumed to contain full entropy.
      *
      * The conversion from Full is implicit so that Entropy_Estimate::Full()
      * can be passed directly to add_entropy.
      */
      constexpr Entropy_Estimate(Full /*unused*/) : m_full(true), m_bits(0) {}  // NOLINT(*-explicit-conversions)

      /**
      * The input is estimated to contain the given number of bits of entropy.
      *
      * An estimate of zero bits means that the input is mixed into the RNG
      * state but is not credited towards the RNG being considered seeded.
      *
      * The conversion from Bits is implicit so that Entropy_Estimate::Bits(n)
      * can be passed directly to add_entropy.
      */
      constexpr Entropy_Estimate(Bits bits) : m_full(false), m_bits(bits.value()) {}  // NOLINT(*-explicit-conversions)

      /**
      * @return true if this estimate assumes full entropy
      */
      constexpr bool is_full() const { return m_full; }

      /**
      * @return the number of bits of entropy credited for an input of
      * @p input_len bytes. A numeric estimate is capped at the bit length
      * of the input.
      */
      constexpr size_t bits_for_input(size_t input_len) const {
         const size_t input_bits = 8 * input_len;
         if(is_full() || m_bits > input_bits) {
            return input_bits;
         }
         return m_bits;
      }

   private:
      bool m_full;
      size_t m_bits;
};

/**
* An interface to a cryptographic random number generator
*/
class BOTAN_PUBLIC_API(2, 0) RandomNumberGenerator {
   public:
      /**
      * Userspace RNGs like HMAC_DRBG will reseed after a specified number
      * of outputs are generated. Set to zero to disable automatic reseeding.
      */
      static constexpr size_t DefaultReseedInterval = 1024;

      /**
      * Number of entropy bits polled for reseeding userspace RNGs like HMAC_DRBG
      */
      static constexpr size_t DefaultPollBits = 256;

      virtual ~RandomNumberGenerator() = default;

      /**
      * Default constructor
      */
      RandomNumberGenerator() = default;

      /*
      * Never copy a RNG, create a new one
      */
      RandomNumberGenerator(const RandomNumberGenerator& rng) = delete;
      RandomNumberGenerator& operator=(const RandomNumberGenerator& rng) = delete;

      /**
      * Move constructor
      */
      RandomNumberGenerator(RandomNumberGenerator&& rng) = default;

      /**
      * Move assignment
      * @return reference to this
      */
      RandomNumberGenerator& operator=(RandomNumberGenerator&& rng) = default;

      /**
      * Randomize a byte array.
      *
      * May block shortly if e.g. the RNG is not yet initialized
      * or a retry because of insufficient entropy is needed.
      *
      * @param output the byte array to hold the random output.
      * @throws PRNG_Unseeded if the RNG fails because it has not enough entropy
      * @throws Exception if the RNG fails
      */
      void randomize(std::span<uint8_t> output) { this->fill_bytes_with_input(output, {}); }

      /**
      * Randomize a byte array
      * @param output the byte array to hold the random output
      * @param length the number of bytes to generate
      */
      void randomize(uint8_t output[], size_t length) { this->randomize(std::span(output, length)); }

      /**
      * Returns false if it is known that this RNG object is not able to accept
      * externally provided inputs (via add_entropy, randomize_with_input, etc).
      * In this case, any such provided inputs are ignored.
      *
      * If this function returns true, then inputs may or may not be accepted.
      */
      virtual bool accepts_input() const = 0;

      /**
      * Incorporate some additional data into the RNG state. For
      * example adding nonces or timestamps from a peer's protocol
      * message can help hedge against VM state rollback attacks.
      * A few RNG types do not accept any externally provided input,
      * in which case this function is a no-op.
      *
      * By default the input is assumed to contain full entropy; for a
      * stateful RNG such as HMAC_DRBG an input of at least security_level()
      * bits then marks the RNG as seeded. Pass an explicit Entropy_Estimate
      * to credit the input differently. In particular Entropy_Estimate::Bits(0)
      * mixes the input into the RNG state without affecting the seeded state,
      * which is appropriate for data of unknown or untrusted quality.
      *
      * @param input a byte array containing the entropy to be added
      * @param estimate the amount of entropy assumed to be contained in input
      * @throws Exception may throw if the RNG accepts input, but adding the entropy failed.
      */
      void add_entropy(std::span<const uint8_t> input, Entropy_Estimate estimate = Entropy_Estimate::Full()) {
         this->add_entropy_with_estimate(input, estimate);
      }

      /**
      * Incorporate some additional data into the RNG state
      * @param input a byte array containing the entropy to be added
      * @param length the number of bytes in input
      * @param estimate the amount of entropy assumed to be contained in input
      */
      void add_entropy(const uint8_t input[], size_t length, Entropy_Estimate estimate = Entropy_Estimate::Full()) {
         this->add_entropy(std::span(input, length), estimate);
      }

      /**
      * Incorporate some additional data into the RNG state.
      * @param t the object whose representation is added to the RNG state
      * @param estimate the amount of entropy assumed to be contained in t
      */
      template <typename T>
         requires std::is_standard_layout_v<T> && std::is_trivial_v<T>
      void add_entropy_T(const T& t, Entropy_Estimate estimate = Entropy_Estimate::Full()) {
         this->add_entropy(reinterpret_cast<const uint8_t*>(&t), sizeof(T), estimate);
      }

      /**
      * Incorporate entropy into the RNG state then produce output.
      * Some RNG types implement this using a single operation, default
      * calls add_entropy + randomize in sequence.
      *
      * Use this to further bind the outputs to your current
      * process/protocol state. For instance if generating a new key
      * for use in a session, include a session ID or other such
      * value. See NIST SP 800-90 A, B, C series for more ideas.
      *
      * @param output buffer to hold the random output
      * @param input entropy buffer to incorporate
      * @throws PRNG_Unseeded if the RNG fails because it has not enough entropy
      * @throws Exception if the RNG fails
      * @throws Exception may throw if the RNG accepts input, but adding the entropy failed.
      */
      void randomize_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) {
         this->fill_bytes_with_input(output, input);
      }

      /**
      * Randomize a byte array, first incorporating additional input
      * @param output the byte array to hold the random output
      * @param output_len the number of bytes to generate
      * @param input a byte array containing the entropy to be added
      * @param input_len the number of bytes in input
      */
      void randomize_with_input(uint8_t output[], size_t output_len, const uint8_t input[], size_t input_len) {
         this->randomize_with_input(std::span(output, output_len), std::span(input, input_len));
      }

      /**
      * This calls `randomize_with_input` using system specific values
      *
      * This first attempts to provide input to the underlying RNG from some system
      * specific source. If a system RNG is available, it is queried and the output from
      * the system RNG is used as the additional input. Otherwise 12 bytes consisting of
      * the local clock plus the current process ID are used.
      *
      * For a stateful RNG that was already correctly seeded with sufficient
      * cryptographically secure material, using non-random but potentially unique data
      * as the extra input can help protect against problems with fork, VM state
      * rollback, or other cases where somehow an RNG state is duplicated. If both of
      * the duplicated RNG states later incorporate some input, even predictable input,
      * their outputs will diverge.
      *
      * @param output buffer to hold the random output
      * @throws PRNG_Unseeded if the RNG fails because it has not enough entropy
      * @throws Exception if the RNG fails
      * @throws Exception may throw if the RNG accepts input, but adding the entropy failed.
      */
      void randomize_with_ts_input(std::span<uint8_t> output);

      /**
      * Randomize a byte array, using timestamps as additional input
      * @param output the byte array to hold the random output
      * @param output_len the number of bytes to generate
      */
      void randomize_with_ts_input(uint8_t output[], size_t output_len) {
         this->randomize_with_ts_input(std::span(output, output_len));
      }

      /**
      * Return the name of this RNG type
      * @return the name of this RNG type
      */
      virtual std::string name() const = 0;

      /**
      * Clear all internally held values of this RNG
      * @post is_seeded() == false if the RNG has an internal state that can be cleared.
      */
      virtual void clear() = 0;

      /**
      * Check whether this RNG is seeded.
      * @return true if this RNG was already seeded, false otherwise.
      */
      virtual bool is_seeded() const = 0;

      /**
      * Poll provided sources for up to poll_bits bits of entropy.
      * Returns estimate of the number of bits collected.
      * Sets the seeded state to true if enough entropy was added.
      *
      * @throws Exception if RNG accepts input but reseeding failed.
      */
      size_t reseed_from(Entropy_Sources& srcs, size_t poll_bits = RandomNumberGenerator::DefaultPollBits) {
         return reseed_from_sources(srcs, poll_bits);
      }

      /**
      * Reseed by reading specified bits from the RNG
      *
      * Sets the seeded state to true if enough entropy was added.
      *
      * @throws Exception if RNG accepts input but reseeding failed.
      */
      void reseed_from(RandomNumberGenerator& rng, size_t poll_bits = RandomNumberGenerator::DefaultPollBits) {
         return reseed_from_rng(rng, poll_bits);
      }

      // Some utility functions built on the interface above:

      /**
      * Fill a given byte container with @p bytes random bytes
      *
      * @todo deprecate this overload (in favor of randomize())
      *
      * @param  v     the container to be filled with @p bytes random bytes
      * @throws Exception if RNG fails
      */
      void random_vec(std::span<uint8_t> v) { this->randomize(v); }

      /**
      * Resize a given byte container to @p bytes and fill it with random bytes
      *
      * @tparam T     the desired byte container type (e.g std::vector<uint8_t>)
      * @param  v     the container to be filled with @p bytes random bytes
      * @param  bytes number of random bytes to initialize the container with
      * @throws Exception if RNG or memory allocation fails
      */
      template <concepts::resizable_byte_buffer T>
      void random_vec(T& v, size_t bytes) {
         v.resize(bytes);
         random_vec(v);
      }

      /**
      * Create some byte container type and fill it with some random @p bytes.
      *
      * @tparam T     the desired byte container type (e.g std::vector<uint8_t>)
      * @param  bytes number of random bytes to initialize the container with
      * @return       a container of type T with @p bytes random bytes
      * @throws Exception if RNG or memory allocation fails
      */
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
         requires std::default_initializable<T>
      T random_vec(size_t bytes) {
         T result;
         random_vec(result, bytes);
         return result;
      }

      /**
       * Create a std::array of @p bytes random bytes
       */
      template <size_t bytes>
      std::array<uint8_t, bytes> random_array() {
         std::array<uint8_t, bytes> result{};
         random_vec(result);
         return result;
      }

      /**
      * Return a random byte
      * @return random byte
      * @throws PRNG_Unseeded if the RNG fails because it has not enough entropy
      * @throws Exception if the RNG fails
      */
      uint8_t next_byte() {
         uint8_t b = 0;
         this->fill_bytes_with_input(std::span(&b, 1), {});
         return b;
      }

      /**
      * Generate a single random byte which is not zero
      * @return a random byte that is greater than zero
      * @throws PRNG_Unseeded if the RNG fails because it has not enough entropy
      * @throws Exception if the RNG fails
      */
      uint8_t next_nonzero_byte() {
         uint8_t b = this->next_byte();
         while(b == 0) {
            b = this->next_byte();
         }
         return b;
      }

      /**
      * Reseed by reading specified bits from the RNG
      *
      * Sets the seeded state to true if enough entropy was added.
      *
      * @throws Exception if RNG accepts input but reseeding failed.
      */
      virtual void reseed_from_rng(RandomNumberGenerator& rng,
                                   size_t poll_bits = RandomNumberGenerator::DefaultPollBits);

#if !defined(BOTAN_IS_BEING_BUILT)
      /**
      * Default poll timeout
      */
      static constexpr auto DefaultPollTimeout = std::chrono::milliseconds(50);

      /**
       * Poll provided sources for up to poll_bits bits of entropy.
       * Returns estimate of the number of bits collected.
       *
       * Sets the seeded state to true if enough entropy was added.
       *
       * TODO(Botan4) remove this function
       */
      BOTAN_DEPRECATED("Use reseed_from_sources")
      inline size_t reseed(Entropy_Sources& srcs,
                           size_t poll_bits = RandomNumberGenerator::DefaultPollBits,
                           std::chrono::milliseconds /*unused_timeout*/ = DefaultPollTimeout) {
         return reseed_from(srcs, poll_bits);
      }
#endif

   protected:
      /**
      * Poll provided sources for up to poll_bits bits of entropy.
      * Returns estimate of the number of bits collected.
      * Sets the seeded state to true if enough entropy was added.
      *
      * @throws Exception if RNG accepts input but reseeding failed.
      */
      virtual size_t reseed_from_sources(Entropy_Sources& srcs,
                                         size_t poll_bits = RandomNumberGenerator::DefaultPollBits);

      /**
      * Incorporate the provided input into the RNG state, crediting it with
      * the given entropy estimate.
      *
      * The default implementation ignores the estimate and forwards the input
      * to fill_bytes_with_input with an empty output buffer. This is the
      * correct behavior for RNGs which do not track whether they are seeded,
      * such as system or hardware RNGs. RNGs which do track a seeded state
      * should override this function and credit the input according to the
      * estimate.
      *
      * @param input the data to incorporate
      * @param estimate the amount of entropy assumed to be contained in input
      */
      virtual void add_entropy_with_estimate(std::span<const uint8_t> input, Entropy_Estimate estimate);

      /**
      * Generic interface to provide entropy to a concrete implementation and to
      * fill a given buffer with random output. Both @p output and @p input may
      * be empty and should be ignored in that case. If both buffers are
      * non-empty implementations should typically first apply the @p input data
      * and then generate random data into @p output.
      *
      * This method must be implemented by all RandomNumberGenerator sub-classes.
      *
      * @param output  Byte buffer to write random bytes into. Implementations
      *                should not read from this buffer.
      * @param input   Byte buffer that may contain bytes to be incorporated in
      *                the RNG's internal state. Implementations may choose to
      *                ignore the bytes in this buffer.
      */
      virtual void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) = 0;
};

/**
* Convenience typedef
*/
typedef RandomNumberGenerator RNG;

/**
* Hardware_RNG exists to tag hardware RNG types (PKCS11_RNG, TPM_RNG, Processor_RNG)
*/
class BOTAN_PUBLIC_API(2, 0) Hardware_RNG : public RandomNumberGenerator {
   public:
      /**
      * No-op clear implementation - no way to clear state of a hardware RNG
      */
      void clear() final {}
};

/**
* Null/stub RNG - fails if you try to use it for anything
* This is not generally useful except for in certain tests
*/
class BOTAN_PUBLIC_API(2, 0) Null_RNG final : public RandomNumberGenerator {
   public:
      /**
      * Test whether this RNG has been seeded
      * @return true if this RNG is seeded and ready for use
      */
      bool is_seeded() const override { return false; }

      /**
      * Test whether this RNG accepts externally provided input
      * @return false if this RNG is known to ignore provided inputs
      */
      bool accepts_input() const override { return false; }

      /**
      * Clear all internally held values of this RNG
      */
      void clear() override {}

      /**
      * Return the name of this RNG type
      * @return the name of this RNG type
      */
      std::string name() const override { return "Null_RNG"; }

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> /* ignored */) override;
};

}  // namespace Botan

#endif
