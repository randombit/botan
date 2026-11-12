/*
* CTR_DRBG (SP800-90A)
* (C) 2023,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CTR_DRBG_H_
#define BOTAN_CTR_DRBG_H_

#include <botan/stateful_rng.h>
#include <memory>
#include <string_view>

namespace Botan {

class BlockCipher;
class Entropy_Sources;

/**
* CTR_DRBG from NIST SP800-90A
*
* The block cipher must have a 128-bit block and a key of 128, 192, or 256
* bits; normally AES is used. The entire 128-bit block is used as the counter.
*/
class BOTAN_PUBLIC_API(3, 15) CTR_DRBG final : public Stateful_RNG {
   public:
      /**
      * Initialize a CTR_DRBG instance with the given block cipher
      *
      * Automatic reseeding is disabled completely, as it has no access to
      * any source for seed material. After 2^48 requests without a reseed
      * an exception is thrown rather than generating output.
      *
      * If a fork is detected, the RNG will be unable to reseed itself
      * in response. In this case, an exception will be thrown rather
      * than generating duplicated output.
      *
      * @param cipher the block cipher to use (normally AES)
      */
      explicit CTR_DRBG(std::unique_ptr<BlockCipher> cipher);

      /**
      * Constructor taking a string for the block cipher
      */
      explicit CTR_DRBG(std::string_view cipher);

      /**
      * Initialize a CTR_DRBG instance with the given block cipher
      *
      * Automatic reseeding from @p underlying_rng will take place after
      * @p reseed_interval many requests or after a fork was detected.
      *
      * @param cipher the block cipher to use (normally AES)
      * @param underlying_rng is a reference to some RNG which will be used
      * to perform the periodic reseeding
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed (max. 2^24)
      * @param max_number_of_bytes_per_request requests that are in size higher
      * than max_number_of_bytes_per_request are treated as if multiple single
      * requests of max_number_of_bytes_per_request size had been made.
      * NIST requires for CTR_DRBG that every implementation set a value no
      * more than 2**19 bits (or 64 KiB).
      */
      CTR_DRBG(std::unique_ptr<BlockCipher> cipher,
               RandomNumberGenerator& underlying_rng,
               size_t reseed_interval = RandomNumberGenerator::DefaultReseedInterval,
               size_t max_number_of_bytes_per_request = 64 * 1024);

      /**
      * Initialize a CTR_DRBG instance with the given block cipher
      *
      * Automatic reseeding from @p entropy_sources will take place after
      * @p reseed_interval many requests or after a fork was detected.
      *
      * @param cipher the block cipher to use (normally AES)
      * @param entropy_sources will be polled to perform reseeding periodically
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed (max. 2^24)
      * @param max_number_of_bytes_per_request requests that are in size higher
      * than max_number_of_bytes_per_request are treated as if multiple single
      * requests of max_number_of_bytes_per_request size had been made.
      * NIST requires for CTR_DRBG that every implementation set a value no
      * more than 2**19 bits (or 64 KiB).
      */
      CTR_DRBG(std::unique_ptr<BlockCipher> cipher,
               Entropy_Sources& entropy_sources,
               size_t reseed_interval = RandomNumberGenerator::DefaultReseedInterval,
               size_t max_number_of_bytes_per_request = 64 * 1024);

      /**
      * Initialize a CTR_DRBG instance with the given block cipher
      *
      * Automatic reseeding from @p underlying_rng and @p entropy_sources
      * will take place after @p reseed_interval many requests or after
      * a fork was detected.
      *
      * @param cipher the block cipher to use (normally AES)
      * @param underlying_rng is a reference to some RNG which will be used
      * to perform the periodic reseeding
      * @param entropy_sources will be polled to perform reseeding periodically
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed (max. 2^24)
      * @param max_number_of_bytes_per_request requests that are in size higher
      * than max_number_of_bytes_per_request are treated as if multiple single
      * requests of max_number_of_bytes_per_request size had been made.
      * NIST requires for CTR_DRBG that every implementation set a value no
      * more than 2**19 bits (or 64 KiB).
      */
      CTR_DRBG(std::unique_ptr<BlockCipher> cipher,
               RandomNumberGenerator& underlying_rng,
               Entropy_Sources& entropy_sources,
               size_t reseed_interval = RandomNumberGenerator::DefaultReseedInterval,
               size_t max_number_of_bytes_per_request = 64 * 1024);

      ~CTR_DRBG() override;

      CTR_DRBG(const CTR_DRBG& rng) = delete;
      CTR_DRBG& operator=(const CTR_DRBG& rng) = delete;

      CTR_DRBG(CTR_DRBG&& rng) = delete;
      CTR_DRBG& operator=(CTR_DRBG&& rng) = delete;

      /**
      * Return the name of this RNG type, eg "CTR_DRBG(AES-256)"
      */
      std::string name() const override;

      /**
      * Return the security level of this DRBG
      * @return the estimated security level in bits
      */
      size_t security_level() const override;

      /**
      * Return how many bits of seed material are required to seed this DRBG
      *
      * This is 3/2 of the security level, since the seed material includes a nonce.
      */
      size_t required_seed_bits() const override;

      /**
      * Return the largest number of bytes this DRBG will produce per request
      * @return the maximum request size in bytes
      */
      size_t max_number_of_bytes_per_request() const override { return m_max_number_of_bytes_per_request; }

   private:
      // Only used to reproduce test vectors, see internal/ctr_drbg_nodf.h
      friend class CTR_DRBG_Without_DF;

      enum class DerivationFunction : uint8_t {
         Enabled,
         Disabled,
      };

      CTR_DRBG(std::unique_ptr<BlockCipher> cipher, DerivationFunction df);

      void update(std::span<const uint8_t> input) override;

      void generate_output(std::span<uint8_t> output, std::span<const uint8_t> input) override;

      void clear_state() override;

      size_t key_length() const { return m_key_length; }

      size_t seed_length() const { return m_key_length + 16; }

      void derive_seed_material(std::span<uint8_t> seed_material, std::span<const uint8_t> input);

      void block_cipher_df(std::span<uint8_t> output, std::span<const uint8_t> input);

      void ctr_drbg_update(std::span<const uint8_t> provided_data);

      void next_counters(std::span<uint8_t> buf);

      void generate_blocks(std::span<uint8_t> output);

      std::unique_ptr<BlockCipher> m_cipher;
      // Both null if the derivation function is disabled, which is only done for testing
      std::unique_ptr<BlockCipher> m_bcc_cipher;  // permanently keyed with the fixed BCC key
      std::unique_ptr<BlockCipher> m_df_cipher;   // keyed with the derived key K
      uint64_t m_V_hi = 0;
      uint64_t m_V_lo = 0;
      const size_t m_key_length;
      const size_t m_max_number_of_bytes_per_request;
};

}  // namespace Botan

#endif
