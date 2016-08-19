/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/stateful_rng.h>
#include <botan/internal/os_utils.h>

namespace Botan {

void Stateful_RNG::clear()
   {
   m_successful_initialization = false;
   m_bytes_since_reseed = 0;
   m_last_pid = 0;
   }

size_t Stateful_RNG::reseed(Entropy_Sources& srcs,
                            size_t poll_bits,
                            std::chrono::milliseconds poll_timeout)
   {
   size_t bits_collected = RandomNumberGenerator::reseed(srcs, poll_bits, poll_timeout);

   if(bits_collected >= security_level())
      {
      m_successful_initialization = true;
      m_bytes_since_reseed = 0;
      }

   return bits_collected;
   }

void Stateful_RNG::reseed_from_rng(RandomNumberGenerator& rng, size_t poll_bits)
   {
   RandomNumberGenerator::reseed_from_rng(rng, poll_bits);

   if(poll_bits >= security_level())
      {
      m_successful_initialization = true;
      m_bytes_since_reseed = 0;
      }
   }

void Stateful_RNG::reseed_check(size_t bytes_requested)
   {
   const bool fork_detected = (m_last_pid > 0) && (OS::get_process_id() != m_last_pid);

   m_bytes_since_reseed += bytes_requested;
   m_last_pid = OS::get_process_id();

   if(!is_seeded() ||
      fork_detected ||
      (m_max_output_before_reseed > 0 && m_bytes_since_reseed >= m_max_output_before_reseed))
      {
      m_successful_initialization = false;

      if(m_underlying_rng)
         {
         reseed_from_rng(*m_underlying_rng, security_level());
         }

      if(m_entropy_sources)
         {
         reseed(*m_entropy_sources, security_level());
         }
      }

   if(!is_seeded())
      {
      if(fork_detected)
         throw Exception("Detected use of fork but cannot reseed DRBG");
      else
         throw PRNG_Unseeded(name());
      }
   }

void Stateful_RNG::initialize_with(const byte input[], size_t len)
   {
   add_entropy(input, len);

   if(8*len >= security_level())
      {
      m_successful_initialization = true;
      m_bytes_since_reseed = 0;
      }
   }

bool Stateful_RNG::is_seeded() const
   {
   return m_successful_initialization;
   }

}
