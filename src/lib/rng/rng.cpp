/*
* Random Number Generator
* (C) 1999-2008,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rng.h>
#include <botan/hmac_drbg.h>
#include <botan/auto_rng.h>
#include <botan/entropy_src.h>
#include <botan/loadstor.h>
#include <botan/internal/os_utils.h>
#include <chrono>

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
   typedef std::chrono::system_clock clock;

   auto deadline = clock::now() + poll_timeout;

   double bits_collected = 0;

   Entropy_Accumulator accum([&](const byte in[], size_t in_len, double entropy_estimate) {
      add_entropy(in, in_len);
      bits_collected += entropy_estimate;
      return (bits_collected >= poll_bits || clock::now() > deadline);
      });

   srcs.poll(accum);

   return bits_collected;
   }

Stateful_RNG::Stateful_RNG(size_t bytes_before_reseed) :
   m_max_bytes_before_reseed_required(bytes_before_reseed)
   {
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
   else if(m_max_bytes_before_reseed_required > 0 &&
           m_bytes_since_reseed >= m_max_bytes_before_reseed_required)
      {
      this->reseed_with_timeout(BOTAN_RNG_AUTO_RESEED_POLL_BITS,
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

AutoSeeded_RNG::AutoSeeded_RNG(size_t max_bytes_before_reseed)
   {
   m_rng.reset(new HMAC_DRBG(BOTAN_AUTO_RNG_DRBG_HASH_FUNCTION, max_bytes_before_reseed));
   size_t bits = m_rng->reseed(384);
   if(!m_rng->is_seeded())
      {
      throw Exception("AutoSeeded_RNG failed to gather enough entropy only got " +
                      std::to_string(bits) + " bits");
      }
   }

void AutoSeeded_RNG::randomize(byte output[], size_t output_len)
   {
   /*
   This data is not secret so skipping a vector/secure_vector allows
   avoiding an allocation.
   */
   typedef std::chrono::high_resolution_clock clock;

   byte nonce_buf[16] = { 0 };
   const uint32_t cur_ctr = m_counter++;
   const uint32_t cur_pid = OS::get_process_id();
   const uint64_t cur_time = clock::now().time_since_epoch().count();

   store_le(cur_ctr,  nonce_buf);
   store_le(cur_pid,  nonce_buf + 4);
   store_le(cur_time, nonce_buf + 8);

   m_rng->randomize_with_input(output, output_len,
                               nonce_buf, sizeof(nonce_buf));

   ++m_counter;
   }

}
