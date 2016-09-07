/*
* HMAC RNG
* (C) 2008,2013,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HMAC_RNG_H__
#define BOTAN_HMAC_RNG_H__

#include <botan/stateful_rng.h>
#include <botan/mac.h>

namespace Botan {

/**
* HMAC_RNG - based on the design described in "On Extract-then-Expand
* Key Derivation Functions and an HMAC-based KDF" by Hugo Krawczyk
* (henceforce, 'E-t-E')
*
* However it actually could be parameterized with any two MAC functions,
* not restricted to HMAC (this variation is also described in
* Krawczyk's paper), for instance one could use HMAC(SHA-512) as the
* extractor and CMAC(AES-256) as the PRF.
*/
class BOTAN_DLL HMAC_RNG final : public Stateful_RNG
   {
   public:
      /**
      * Initialize an HMAC_RNG instance with the given MAC as PRF (normally HMAC)
      * @param underlying_rng is a reference to some RNG which will be used
      * to perform the periodic reseeding.
      * @param entropy_sources will be polled to perform reseeding periodically
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed.
      */
      HMAC_RNG(std::unique_ptr<MessageAuthenticationCode> prf,
               RandomNumberGenerator& underlying_rng,
               Entropy_Sources& entropy_sources,
               size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL);

      /**
      * Initialize an HMAC_RNG instance with the given MAC as PRF (normally HMAC)
      * @param underlying_rng is a reference to some RNG which will be used
      * to perform the periodic reseeding.
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed.
      */
      HMAC_RNG(std::unique_ptr<MessageAuthenticationCode> prf,
               RandomNumberGenerator& underlying_rng,
               size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL);

      /*
      * Initialize an HMAC_RNG instance with the given MAC as PRF (normally HMAC)
      * @param entropy_sources will be polled to perform reseeding periodically
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed.
      */
      HMAC_RNG(std::unique_ptr<MessageAuthenticationCode> prf,
               Entropy_Sources& entropy_sources,
               size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL);

      /**
      * Initialize an HMAC_RNG instance with the given MAC as PRF (normally HMAC)
      * Automatic reseeding is disabled completely.
      */
      HMAC_RNG(std::unique_ptr<MessageAuthenticationCode> prf);

      void randomize(byte buf[], size_t len) override;
      void clear() override;
      std::string name() const override;

      size_t reseed(Entropy_Sources& srcs,
                    size_t poll_bits,
                    std::chrono::milliseconds poll_timeout) override;

      void add_entropy(const byte[], size_t) override;

      size_t security_level() const override { return m_prf->output_length() * 8 / 2; }

   private:
      std::unique_ptr<MessageAuthenticationCode> m_prf;
      std::unique_ptr<MessageAuthenticationCode> m_extractor;

      enum HMAC_PRF_Label {
         Running,
         BlockFinished,
         Reseed,
         ExtractorSeed,
      };
      void new_K_value(byte label);

      secure_vector<byte> m_K;
      u32bit m_counter = 0;
   };

}

#endif
