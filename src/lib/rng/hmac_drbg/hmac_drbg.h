/*
* HMAC_DRBG (SP800-90A)
* (C) 2014,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HMAC_DRBG_H__
#define BOTAN_HMAC_DRBG_H__

#include <botan/rng.h>
#include <botan/mac.h>

namespace Botan {

/**
* HMAC_DRBG from NIST SP800-90A
*/
class BOTAN_DLL HMAC_DRBG final : public Stateful_RNG
   {
   public:
      /**
      * Initialize an HMAC_DRBG instance with the given hash function
      */
      HMAC_DRBG(const std::string& hmac_hash,
                size_t max_output_before_reseed = BOTAN_RNG_DEFAULT_MAX_OUTPUT_BEFORE_RESEED);

      HMAC_DRBG(MessageAuthenticationCode* hmac,
                size_t max_output_before_reseed = BOTAN_RNG_DEFAULT_MAX_OUTPUT_BEFORE_RESEED);

      std::string name() const override;

      void clear() override;

      void randomize(byte output[], size_t output_len) override;

      void randomize_with_input(byte output[], size_t output_len,
                                const byte input[], size_t input_len) override;

      void add_entropy(const byte input[], size_t input_len) override;
   private:
      void update(const byte input[], size_t input_len);

      std::unique_ptr<MessageAuthenticationCode> m_mac;
      secure_vector<byte> m_V;
   };

}

#endif
