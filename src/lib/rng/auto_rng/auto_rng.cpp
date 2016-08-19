/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/auto_rng.h>
#include <botan/entropy_src.h>
#include <botan/loadstor.h>
#include <botan/internal/os_utils.h>

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

   if(!m_rng->is_seeded())
      {
      m_rng->next_byte();
      BOTAN_ASSERT(m_rng->is_seeded(), "ok");
      //throw Exception("AutoSeeded_RNG failed to generate seed material");
      }
   }

void AutoSeeded_RNG::randomize(byte output[], size_t output_len)
   {
   /*
   Form additional input which is provided to the PRNG implementation
   to paramaterize the KDF output.
   */
   byte additional_input[24] = { 0 };
   store_le(OS::get_system_timestamp_ns(), additional_input);
   store_le(OS::get_processor_timestamp(), additional_input + 8);
   store_le(OS::get_process_id(), additional_input + 16);
   store_le(m_counter++, additional_input + 20);

   randomize_with_input(output, output_len, additional_input, sizeof(additional_input));
   }

void AutoSeeded_RNG::randomize_with_input(byte output[], size_t output_len,
                                          const byte ad[], size_t ad_len)
   {
   m_rng->randomize_with_input(output, output_len, ad, ad_len);
   }

}
