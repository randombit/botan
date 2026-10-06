/*
* (C) 2016,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/stateful_rng.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/internal/os_utils.h>

#if defined(BOTAN_HAS_ENTROPY_SOURCE)
   #include <botan/entropy_src.h>
#endif

namespace Botan {

void Stateful_RNG::clear() {
   const lock_guard_type<recursive_mutex_type> lock(m_mutex);
   m_reseed_counter = 0;
   m_last_pid = 0;
   m_fork_generation = 0;
   clear_state();
}

void Stateful_RNG::force_reseed() {
   const lock_guard_type<recursive_mutex_type> lock(m_mutex);
   m_reseed_counter = 0;
}

bool Stateful_RNG::is_seeded() const {
   const lock_guard_type<recursive_mutex_type> lock(m_mutex);
   return m_reseed_counter > 0;
}

void Stateful_RNG::initialize_with(std::span<const uint8_t> input) {
   const lock_guard_type<recursive_mutex_type> lock(m_mutex);

   clear();
   add_entropy(input);
}

void Stateful_RNG::generate_batched_output(std::span<uint8_t> output, std::span<const uint8_t> input) {
   BOTAN_ASSERT_NOMSG(!output.empty());

   const size_t max_per_request = max_number_of_bytes_per_request();

   if(max_per_request == 0) {
      // no limit
      reseed_check();
      this->generate_output(output, input);
   } else {
      while(!output.empty()) {
         const size_t this_req = std::min(max_per_request, output.size());

         reseed_check();
         this->generate_output(output.subspan(0, this_req), input);

         // only include the input for the first iteration
         input = {};

         output = output.subspan(this_req);
      }
   }
}

void Stateful_RNG::accept_seed_material(std::span<const uint8_t> input) {
   const lock_guard_type<recursive_mutex_type> lock(m_mutex);

   this->update(input);

   // The contract of add_entropy is that the caller asserts full entropy
   if(8 * input.size() >= security_level()) {
      const bool can_reseed = (m_underlying_rng != nullptr || m_entropy_sources != nullptr);

      if(can_reseed && fork_detected()) {
         // The input may be identical in parent and child, so leave the
         // fork pending for reseed_check to handle
         m_reseed_counter = 1;
      } else {
         reset_reseed_counter();
      }
   }
}

void Stateful_RNG::fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) {
   const lock_guard_type<recursive_mutex_type> lock(m_mutex);

   if(output.empty()) {
      // Additional input without output is mixed in but never credited
      this->update(input);
   } else {
      generate_batched_output(output, input);
   }
}

size_t Stateful_RNG::finish_reseed(size_t bits_collected) {
   // Lock is held whenever this function is called
   if(bits_collected >= security_level()) {
      reset_reseed_counter();
   }
   return bits_collected;
}

size_t Stateful_RNG::reseed_from_sources(Entropy_Sources& srcs, size_t poll_bits) {
   const lock_guard_type<recursive_mutex_type> lock(m_mutex);

#if defined(BOTAN_HAS_ENTROPY_SOURCE)
   Entropy_Accumulator acc(poll_bits, [this](std::span<const uint8_t> in) { this->update(in); });
   srcs._gather(acc);
   return finish_reseed(acc.bits_collected());
#else
   BOTAN_UNUSED(srcs, poll_bits);
   return finish_reseed(0);
#endif
}

void Stateful_RNG::reseed_from_rng(RandomNumberGenerator& rng, size_t poll_bits) {
   const lock_guard_type<recursive_mutex_type> lock(m_mutex);

   const auto seed = rng.random_vec(poll_bits / 8);
   this->update(seed);

   // The caller designated this RNG as a seed source, so its output is credited in full
   finish_reseed(8 * seed.size());
}

void Stateful_RNG::reset_reseed_counter() {
   // Lock is held whenever this function is called
   m_reseed_counter = 1;
   m_last_pid = OS::get_process_id();
   m_fork_generation = OS::get_fork_generation();
}

bool Stateful_RNG::fork_detected() const {
   // Lock is held whenever this function is called
   if(m_last_pid == 0) {
      return false;
   }

   return (OS::get_process_id() != m_last_pid || OS::get_fork_generation() != m_fork_generation);
}

void Stateful_RNG::reseed_check() {
   // Lock is held whenever this function is called

   const bool fork_detected = this->fork_detected();

   if(is_seeded() == false || fork_detected || (m_reseed_interval > 0 && m_reseed_counter >= m_reseed_interval)) {
      // The fork baselines are only updated by a successful reseed
      m_reseed_counter = 0;

      if(m_underlying_rng != nullptr) {
         reseed_from_rng(*m_underlying_rng, security_level());
      }

      if(m_entropy_sources != nullptr) {
         reseed_from_sources(*m_entropy_sources, security_level());
      }

      if(!is_seeded()) {
         if(fork_detected) {
            throw Invalid_State("Detected use of fork but cannot reseed DRBG");
         } else {
            throw PRNG_Unseeded(name());
         }
      }
   } else {
      BOTAN_ASSERT(m_reseed_counter != 0, "RNG is seeded");
      m_reseed_counter += 1;
   }
}

}  // namespace Botan
