/*
* Random Number Generator
* (C) 1999-2008,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rng.h>
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

namespace Botan {

size_t RandomNumberGenerator::reseed(size_t bits_to_collect)
   {
   return this->reseed_with_timeout(bits_to_collect,
                                    BOTAN_RNG_RESEED_DEFAULT_TIMEOUT);
   }

size_t RandomNumberGenerator::reseed_with_timeout(size_t bits_to_collect,
                                                  std::chrono::milliseconds timeout)
   {
   return this->reseed_with_sources(Entropy_Sources::global_sources(),
                                    bits_to_collect,
                                    timeout);
   }

size_t RandomNumberGenerator::reseed_with_sources(Entropy_Sources& srcs,
                                                  size_t poll_bits,
                                                  std::chrono::milliseconds poll_timeout)
   {
   return srcs.poll(*this, poll_bits, poll_timeout);
   }

Stateful_RNG::Stateful_RNG(size_t max_output_before_reseed) : m_max_output_before_reseed(max_output_before_reseed)
   {
   }

void Stateful_RNG::clear()
   {
   m_successful_initialization = false;
   m_bytes_since_reseed = 0;
   m_last_pid = 0;
   }

size_t Stateful_RNG::reseed_with_sources(Entropy_Sources& srcs,
                                         size_t poll_bits,
                                         std::chrono::milliseconds poll_timeout)
   {
   size_t bits_collected = RandomNumberGenerator::reseed_with_sources(srcs, poll_bits, poll_timeout);

   if(bits_collected >= poll_bits)
      {
      m_successful_initialization = true;
      m_bytes_since_reseed = 0;
      }

   return bits_collected;
   }

void Stateful_RNG::reseed_check(size_t bytes_requested)
   {
   const bool fork_detected = (m_last_pid > 0) && (OS::get_process_id() != m_last_pid);

   m_bytes_since_reseed += bytes_requested;
   m_last_pid = OS::get_process_id();

   if(!is_seeded() || fork_detected)
      {
      this->reseed(BOTAN_RNG_RESEED_POLL_BITS);
      }
   else if(m_max_output_before_reseed > 0 && m_bytes_since_reseed >= m_max_output_before_reseed)
      {
      this->reseed_with_timeout(BOTAN_RNG_RESEED_POLL_BITS,
                                BOTAN_RNG_AUTO_RESEED_TIMEOUT);
      }

   if(!is_seeded())
      {
      throw PRNG_Unseeded(name());
      }
   }

void Stateful_RNG::initialize_with(const byte input[], size_t len)
   {
   add_entropy(input, len);
   m_successful_initialization = true;
   }

bool Stateful_RNG::is_seeded() const
   {
   return m_successful_initialization;
   }

RandomNumberGenerator* RandomNumberGenerator::make_rng()
   {
   return new AutoSeeded_RNG;
   }

AutoSeeded_RNG::AutoSeeded_RNG(size_t max_output_before_reseed)
   {
   m_rng.reset(new BOTAN_AUTO_RNG_DRBG(BOTAN_AUTO_RNG_HASH, max_output_before_reseed));

   size_t bits = m_rng->reseed(BOTAN_AUTO_RNG_ENTROPY_TARGET);

   if(!m_rng->is_seeded())
      {
      throw Exception("AutoSeeded_RNG failed to gather enough entropy only got " +
                      std::to_string(bits) + " bits");
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
