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
      HMAC_DRBG(const std::string& hmac_hash);

      HMAC_DRBG(const std::string& hmac_hash,
                size_t max_bytes_before_reseed);

      std::string name() const override;

      void clear() override;

      void randomize(byte output[], size_t output_len);

      void randomize_with_input(byte output[], size_t output_len,
                                const byte input[], size_t input_len);

      void add_entropy(const byte input[], size_t input_len) override;
   private:
      void update(const byte input[], size_t input_len);

      std::unique_ptr<MessageAuthenticationCode> m_mac;
      secure_vector<byte> m_V;
   };

}

#endif
