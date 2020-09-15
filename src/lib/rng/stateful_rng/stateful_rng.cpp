/*
* (C) 2016,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/stateful_rng.h>
#include <botan/internal/os_utils.h>
#include <botan/loadstor.h>

#if defined(BOTAN_HAS_SYSTEM_RNG)
  #include <botan/system_rng.h>
#endif

namespace Botan {

void Stateful_RNG::clear()
   {
   lock_guard_type<recursive_mutex_type> lock(m_mutex);
   m_reseed_counter = 0;
   m_last_pid = 0;
   clear_state();
   }

void Stateful_RNG::force_reseed()
   {
   lock_guard_type<recursive_mutex_type> lock(m_mutex);
   m_reseed_counter = 0;
   }

bool Stateful_RNG::is_seeded() const
   {
   lock_guard_type<recursive_mutex_type> lock(m_mutex);
   return m_reseed_counter > 0;
   }

void Stateful_RNG::add_entropy(const uint8_t input[], size_t input_len)
   {
   lock_guard_type<recursive_mutex_type> lock(m_mutex);

   update(input, input_len);

   if(8*input_len >= security_level())
      {
      reset_reseed_counter();
      }
   }

void Stateful_RNG::initialize_with(const uint8_t input[], size_t len)
   {
   lock_guard_type<recursive_mutex_type> lock(m_mutex);

   clear();
   add_entropy(input, len);
   }

void Stateful_RNG::randomize(uint8_t output[], size_t output_len)
   {
   randomize_with_input(output, output_len, nullptr, 0);
   }

void Stateful_RNG::randomize_with_ts_input(uint8_t output[], size_t output_len)
   {
   uint8_t additional_input[20] = { 0 };

   store_le(OS::get_high_resolution_clock(), additional_input);

#if defined(BOTAN_HAS_SYSTEM_RNG)
   System_RNG system_rng;
   system_rng.randomize(additional_input + 8, sizeof(additional_input) - 8);
#else
   store_le(OS::get_system_timestamp_ns(), additional_input + 8);
   store_le(OS::get_process_id(), additional_input + 16);
#endif

   randomize_with_input(output, output_len, additional_input, sizeof(additional_input));
   }

void Stateful_RNG::randomize_with_input(uint8_t output[], size_t output_len,
                                        const uint8_t input[], size_t input_len)
   {
   if(output_len == 0)
      return;

   lock_guard_type<recursive_mutex_type> lock(m_mutex);

   const size_t max_per_request = max_number_of_bytes_per_request();

   if(max_per_request == 0) // no limit
      {
      reseed_check();
      this->generate_output(output, output_len, input, input_len);
      }
   else
      {
      while(output_len > 0)
         {
         const size_t this_req = std::min(max_per_request, output_len);

         /*
         * We split the request into several requests to the underlying DRBG but
         * pass the input to each invocation. It might be more sensible to only
         * provide it for the first invocation, however between 2.0 and 2.15
         * HMAC_DRBG always provided it for all requests so retain that here.
         */

         reseed_check();
         this->generate_output(output, this_req, input, input_len);

         output += this_req;
         output_len -= this_req;
         }
      }
   }

size_t Stateful_RNG::reseed(Entropy_Sources& srcs,
                            size_t poll_bits,
                            std::chrono::milliseconds poll_timeout)
   {
   lock_guard_type<recursive_mutex_type> lock(m_mutex);

   const size_t bits_collected = RandomNumberGenerator::reseed(srcs, poll_bits, poll_timeout);

   if(bits_collected >= security_level())
      {
      reset_reseed_counter();
      }

   return bits_collected;
   }

void Stateful_RNG::reseed_from_rng(RandomNumberGenerator& rng, size_t poll_bits)
   {
   lock_guard_type<recursive_mutex_type> lock(m_mutex);

   RandomNumberGenerator::reseed_from_rng(rng, poll_bits);

   if(poll_bits >= security_level())
      {
      reset_reseed_counter();
      }
   }

void Stateful_RNG::reset_reseed_counter()
   {
   // Lock is held whenever this function is called
   m_reseed_counter = 1;
   }

void Stateful_RNG::reseed_check()
   {
   // Lock is held whenever this function is called

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
            throw Invalid_State("Detected use of fork but cannot reseed DRBG");
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
