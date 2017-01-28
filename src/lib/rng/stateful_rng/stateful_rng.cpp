/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/stateful_rng.h>
#include <botan/internal/os_utils.h>
#include <botan/loadstor.h>

namespace Botan {

void Stateful_RNG::clear()
   {
   m_reseed_counter = 0;
   m_last_pid = 0;
   }

void Stateful_RNG::force_reseed()
   {
   m_reseed_counter = 0;
   }

bool Stateful_RNG::is_seeded() const
   {
   return m_reseed_counter > 0;
   }

void Stateful_RNG::initialize_with(const uint8_t input[], size_t len)
   {
   add_entropy(input, len);

   if(8*len >= security_level())
      {
      m_reseed_counter = 1;
      }
   }

void Stateful_RNG::randomize_with_ts_input(uint8_t output[], size_t output_len)
   {
   uint8_t additional_input[24] = { 0 };
   store_le(OS::get_system_timestamp_ns(), additional_input);
   store_le(OS::get_high_resolution_clock(), additional_input + 8);
   store_le(m_last_pid, additional_input + 16);
   store_le(static_cast<uint32_t>(m_reseed_counter), additional_input + 20);

   randomize_with_input(output, output_len, additional_input, sizeof(additional_input));
   }

size_t Stateful_RNG::reseed(Entropy_Sources& srcs,
                            size_t poll_bits,
                            std::chrono::milliseconds poll_timeout)
   {
   size_t bits_collected = RandomNumberGenerator::reseed(srcs, poll_bits, poll_timeout);

   if(bits_collected >= security_level())
      {
      m_reseed_counter = 1;
      }

   return bits_collected;
   }

void Stateful_RNG::reseed_from_rng(RandomNumberGenerator& rng, size_t poll_bits)
   {
   RandomNumberGenerator::reseed_from_rng(rng, poll_bits);

   if(poll_bits >= security_level())
      {
      m_reseed_counter = 1;
      }
   }

void Stateful_RNG::reseed_check()
   {
   const uint32_t cur_pid = OS::get_process_id();

   const bool fork_detected = (m_last_pid > 0) && (cur_pid != m_last_pid);

   if(is_seeded() == false ||
      fork_detected ||
      (m_reseed_interval > 0 && m_reseed_counter >= m_reseed_interval))
      {
      m_reseed_counter = 0;
      m_last_pid = cur_pid;

      if(m_underlying_rng)
         {
         reseed_from_rng(*m_underlying_rng, security_level());
         }

      if(m_entropy_sources)
         {
         reseed(*m_entropy_sources, security_level());
         }

      if(!is_seeded())
         {
         if(fork_detected)
            throw Exception("Detected use of fork but cannot reseed DRBG");
         else
            throw PRNG_Unseeded(name());
         }
      }
   else
      {
      BOTAN_ASSERT(m_reseed_counter != 0, "RNG is seeded");
      m_reseed_counter += 1;
      }
   }

}
