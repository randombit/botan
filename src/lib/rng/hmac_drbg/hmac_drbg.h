/*
* HMAC_DRBG (SP800-90A)
* (C) 2014,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HMAC_DRBG_H__
#define BOTAN_HMAC_DRBG_H__

#include <botan/stateful_rng.h>
#include <botan/mac.h>

namespace Botan {

class Entropy_Sources;

/**
* HMAC_DRBG from NIST SP800-90A
*/
class BOTAN_DLL HMAC_DRBG final : public Stateful_RNG
   {
   public:
      /**
      * Initialize an HMAC_DRBG instance with the given MAC as PRF (normally HMAC)
      *
      * Automatic reseeding is disabled completely, as it as no access to
      * any source for seed material.
      *
      * If a fork is detected, the RNG will be unable to reseed itself
      * in response. In this case, an exception will be thrown rather
      * than generating duplicated output.
      */
      HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf);

      /**
      * Initialize an HMAC_DRBG instance with the given MAC as PRF (normally HMAC)
      *
      * @param underlying_rng is a reference to some RNG which will be used
      * to perform the periodic reseeding
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed.
      */
      HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf,
                RandomNumberGenerator& underlying_rng,
                size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL);

      /**
      * Initialize an HMAC_DRBG instance with the given MAC as PRF (normally HMAC)
      *
      * @param entropy_sources will be polled to perform reseeding periodically
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed.
      */
      HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf,
                Entropy_Sources& entropy_sources,
                size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL);

      /**
      * Initialize an HMAC_DRBG instance with the given MAC as PRF (normally HMAC)
      *
      * @param underlying_rng is a reference to some RNG which will be used
      * to perform the periodic reseeding
      * @param entropy_sources will be polled to perform reseeding periodically
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed.
      */
      HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf,
                RandomNumberGenerator& underlying_rng,
                Entropy_Sources& entropy_sources,
                size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL);

      /**
      * Constructor taking a string for the hash
      */
      HMAC_DRBG(const std::string& hmac_hash) : Stateful_RNG()
         {
         m_mac = MessageAuthenticationCode::create("HMAC(" + hmac_hash + ")");
         if(!m_mac)
            throw Algorithm_Not_Found(hmac_hash);
         clear();
         }

      std::string name() const override;

      void clear() override;

      void randomize(byte output[], size_t output_len) override;

      void randomize_with_input(byte output[], size_t output_len,
                                const byte input[], size_t input_len) override;

      void add_entropy(const byte input[], size_t input_len) override;

      size_t security_level() const override;

   private:
      void update(const byte input[], size_t input_len);

      std::unique_ptr<MessageAuthenticationCode> m_mac;
      secure_vector<byte> m_V;
   };

}

#endif
