/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/auto_rng.h>
#include <botan/entropy_src.h>

#if defined(BOTAN_HAS_HMAC_DRBG)
  #include <botan/hmac_drbg.h>
#endif

#if defined(BOTAN_HAS_HMAC_RNG)
  #include <botan/hmac_rng.h>
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
  #include <botan/system_rng.h>
#endif

namespace Botan {

AutoSeeded_RNG::AutoSeeded_RNG(size_t max_output_before_reseed)
   {
   m_rng.reset(new BOTAN_AUTO_RNG_DRBG(MessageAuthenticationCode::create(BOTAN_AUTO_RNG_HMAC),
#if defined(BOTAN_HAS_SYSTEM_RNG)
                                       system_rng(),
#else
                                       Entropy_Sources::global_sources(),
#endif
                                       max_output_before_reseed));

   // Initially RNG is unseeded, this will force a reseed:
   m_rng->randomize(nullptr, 0);

   if(!m_rng->is_seeded())
      {
      throw Exception("AutoSeeded_RNG failed initial seeding");
      }
   }

void AutoSeeded_RNG::randomize(byte output[], size_t output_len)
   {
   randomize_with_ts_input(output, output_len);
   }

void AutoSeeded_RNG::randomize_with_input(byte output[], size_t output_len,
                                          const byte ad[], size_t ad_len)
   {
   m_rng->randomize_with_input(output, output_len, ad, ad_len);
   }

}
