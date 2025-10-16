/*
* ChaCha_RNG
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CHACHA_RNG_H_
#define BOTAN_CHACHA_RNG_H_

#include <botan/mac.h>
#include <botan/stateful_rng.h>
#include <botan/stream_cipher.h>

namespace Botan {

class Entropy_Sources;

/**
* ChaCha_RNG is a very fast but completely ad-hoc RNG created by
* creating a 256-bit random value and using it as a key for ChaCha20.
*
* The RNG maintains a 512-bit and a 256-bit key, one for HMAC_SHA512 (HK)
* and the other for ChaCha20 (CK). To compute a new key in response to
* reseeding request or add_entropy calls, ChaCha_RNG computes
*   CK' = HMAC_SHA512(HK, input_material)
* Then a new HK' is computed by running ChaCha20 with the new key to
* output 32 bytes:
*   HK' = ChaCha20(CK')
*
* Now output can be produced by continuing to produce output with ChaCha20
* under CK'
*
* If fast key erasure rekeying is set in the constructor, CK gets overwritten
* by additional output from ChaCha20 after each generate operation.
*  CK' = ChaCha20(CK)
* This costs performance, but can be used when backtracking resistance
* of the internal state is desired (e.g. for usage in DRG.3 or DRT.1
* context of the German AIS 20/31 scheme).
*
* The first HK (before seeding occurs) is taken as the all zero value.
*
* @warning This RNG construction is probably fine but is non-standard.
* The primary reason to use it is in cases where the other RNGs are
* not fast enough.
*
* # Short rationale of design choices:
* - (re-)seeding with HMAC(SHA-512) has the advantage, that inputs
*   do not need to have a fixed length and full entropy over a uniform
*   distribution, they just need to contain enough entropy (e.g. more
*   than 240 bit min-entropy). Using SHA-512 over SHA-256 as the underlying
*   primitive has the advantage of a wider internal width and less
*   entropy loss when hashing.
* - Using ChaCha as stream cipher has the advantage of no entropy loss
*   regarding its seed due to being a random permutation for each key.
*   Furthermore ChaCha has a 512 bit block width, which shifts block
*   collisions in a very unlikely range (regarding output block count).
* - Using ChaCha(20) instead of ChaCha(8) or ChaCha(12) has the
*   advantage of being a conservative choice also taken by the
*   Linux kernel, where it is already accepted as a secure CSPRNG
*   implementation by many people and organizations.
* - Providing optional fast key erasure is necessary to reach
*   backtracking resistance of the internal state. This costs
*   performance depending on the request sizes of the user.
*   It's of course more expensive to rekey on every 4 byte output,
*   than let's say 1024 byte buffers.
*   Because of these performance reasons, it has to be enabled explicitly.
* - Also set nonce/IV of ChaCha when (re-)seeding and rekeying, to effectively
*   extend effective internal high entropy state by 64 bit.
*/
class BOTAN_PUBLIC_API(2, 3) ChaCha_RNG final : public Stateful_RNG {
   private:  // constants
      static constexpr std::string_view stream_cipher_algo = "ChaCha(20)";
      static constexpr std::string_view hmac_algo = "HMAC(SHA-512)";

      // use maximum key length providing 256 bit security
      static constexpr size_t chacha_key_len = 32;
      // use "classic" 8 byte nonce as extended key material
      static constexpr size_t chacha_iv_len = 8;

   public:
      /**
      * Automatic reseeding is disabled completely, as it has no access to
      * any source for seed material.
      *
      * If a fork is detected, the RNG will be unable to reseed itself
      * in response. In this case, an exception will be thrown rather
      * than generating duplicated output.
      *
      * @param fast_key_erasure overwrite state after each operation
      * for backtracking resistance, costs performance depending
      * on request size mix, deactivated by default
      */
      explicit ChaCha_RNG(bool fast_key_erasure = false);

      /**
      * Provide an initial seed to the RNG, without providing an
      * underlying RNG or entropy source. Automatic reseeding is
      * disabled completely, as it has no access to any source for
      * seed material.
      *
      * If a fork is detected, the RNG will be unable to reseed itself
      * in response. In this case, an exception will be thrown rather
      * than generating duplicated output.
      *
      * @param seed the seed material, should be at least 256 bits
      * @param fast_key_erasure overwrite state after each operation
      * for backtracking resistance, costs performance depending
      * on request size mix, deactivated by default
      */
      BOTAN_FUTURE_EXPLICIT ChaCha_RNG(std::span<const uint8_t> seed, bool fast_key_erasure = false);

      /**
      * Automatic reseeding from @p underlying_rng will take place after
      * @p reseed_interval many requests or after a fork was detected.
      *
      * @param underlying_rng is a reference to some RNG which will be used
      * to perform the periodic reseeding
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed
      * @param fast_key_erasure overwrite state after each operation
      * for backtracking resistance, costs performance depending
      * on request size mix, deactivated by default
      */
      BOTAN_FUTURE_EXPLICIT ChaCha_RNG(RandomNumberGenerator& underlying_rng,
                                       size_t reseed_interval = RandomNumberGenerator::DefaultReseedInterval,
                                       bool fast_key_erasure = false);

      /**
      * Automatic reseeding from @p entropy_sources will take place after
      * @p reseed_interval many requests or after a fork was detected.
      *
      * @param entropy_sources will be polled to perform reseeding periodically
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed.
      * @param fast_key_erasure overwrite state after each operation
      * for backtracking resistance, costs performance depending
      * on request size mix, deactivated by default
      */
      BOTAN_FUTURE_EXPLICIT ChaCha_RNG(Entropy_Sources& entropy_sources,
                                       size_t reseed_interval = RandomNumberGenerator::DefaultReseedInterval,
                                       bool fast_key_erasure = false);

      /**
      * Automatic reseeding from @p underlying_rng and @p entropy_sources
      * will take place after @p reseed_interval many requests or after
      * a fork was detected.
      *
      * @param underlying_rng is a reference to some RNG which will be used
      * to perform the periodic reseeding
      * @param entropy_sources will be polled to perform reseeding periodically
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed.
      * @param fast_key_erasure overwrite state after each operation
      * for backtracking resistance, costs performance depending
      * on request size mix, deactivated by default
      */
      ChaCha_RNG(RandomNumberGenerator& underlying_rng,
                 Entropy_Sources& entropy_sources,
                 size_t reseed_interval = RandomNumberGenerator::DefaultReseedInterval,
                 bool fast_key_erasure = false);

      std::string name() const override { return "ChaCha_RNG"; }

      size_t security_level() const override;

      size_t max_number_of_bytes_per_request() const override { return 0; }

      bool fast_key_erasure() const { return m_fast_key_erasure; }

   private:
      void update(std::span<const uint8_t> input) override;

      void generate_output(std::span<uint8_t> output, std::span<const uint8_t> input) override;

      void clear_state() override;

      void update_chacha_state(std::span<const uint8_t> key_material);

      std::unique_ptr<MessageAuthenticationCode> m_hmac;
      std::unique_ptr<StreamCipher> m_chacha;
      bool m_fast_key_erasure;
};

}  // namespace Botan

#endif
