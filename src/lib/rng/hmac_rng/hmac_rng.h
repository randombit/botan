/*
* HMAC RNG
* (C) 2008,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HMAC_RNG_H__
#define BOTAN_HMAC_RNG_H__

#include <botan/mac.h>
#include <botan/rng.h>
#include <vector>

namespace Botan {

/**
* HMAC_RNG - based on the design described in "On Extract-then-Expand
* Key Derivation Functions and an HMAC-based KDF" by Hugo Krawczyk
* (henceforce, 'E-t-E')
*
* However it actually can be parameterized with any two MAC functions,
* not restricted to HMAC (this variation is also described in
* Krawczyk's paper), for instance one could use HMAC(SHA-512) as the
* extractor and CMAC(AES-256) as the PRF.
*/
class BOTAN_DLL HMAC_RNG : public Stateful_RNG
   {
   public:
      void randomize(byte buf[], size_t len) override;
      void clear() override;
      std::string name() const override;

      size_t reseed_with_sources(Entropy_Sources& srcs,
                                 size_t poll_bits,
                                 std::chrono::milliseconds poll_timeout) override;

      void add_entropy(const byte[], size_t) override;

      /**
      * @param extractor a MAC used for extracting the entropy
      * @param prf a MAC used as a PRF using HKDF construction
      */
      HMAC_RNG(MessageAuthenticationCode* extractor,
               MessageAuthenticationCode* prf,
               size_t max_output_before_reseed = BOTAN_RNG_DEFAULT_MAX_OUTPUT_BEFORE_RESEED);

      /**
      * Use the specified hash for both the extractor and PRF functions
      */
      HMAC_RNG(const std::string& hash,
               size_t max_output_before_reseed = BOTAN_RNG_DEFAULT_MAX_OUTPUT_BEFORE_RESEED);
   private:
      std::unique_ptr<MessageAuthenticationCode> m_extractor;
      std::unique_ptr<MessageAuthenticationCode> m_prf;

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
