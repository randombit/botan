/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/auto_rng.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/hmac_drbg.h>
#include <botan/mac.h>

#if defined(BOTAN_HAS_ENTROPY_SOURCE)
   #include <botan/entropy_src.h>
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
   #include <botan/system_rng.h>
#endif

#if defined(BOTAN_HAS_CPUID)
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

namespace {

std::unique_ptr<MessageAuthenticationCode> auto_rng_hmac() {
   const bool has_hardware_sha256_support = []() {
#if defined(BOTAN_HAS_SHA2_32_X86)
      if(CPUID::has(CPUID::Feature::SHA)) {
         return true;
      }
#endif

#if defined(BOTAN_HAS_SHA2_32_ARMV8)
      if(CPUID::has(CPUID::Feature::SHA2)) {
         return true;
      }
#endif

      return false;
   }();

   // On 64-bit systems prefer SHA-512, unless there is support for SHA-256 instructions
   if(!has_hardware_sha256_support && HasNative64BitRegisters) {
      if(auto mac = MessageAuthenticationCode::create("HMAC(SHA-512)")) {
         return mac;
      }
   }

   // Either SHA-512 is unavailable, or SHA-256 is preferable
   if(auto mac = MessageAuthenticationCode::create("HMAC(SHA-256)")) {
      return mac;
   }

   // This shouldn't happen since this module has a dependency on sha2_32
   throw Internal_Error("AutoSeeded_RNG: No usable HMAC hash found");
}

}  // namespace

AutoSeeded_RNG::AutoSeeded_RNG(AutoSeeded_RNG&& other) noexcept = default;

AutoSeeded_RNG::~AutoSeeded_RNG() = default;

AutoSeeded_RNG::AutoSeeded_RNG(RandomNumberGenerator& underlying_rng, size_t reseed_interval) {
   m_rng = std::make_unique<HMAC_DRBG>(auto_rng_hmac(), underlying_rng, reseed_interval);

   force_reseed();
}

AutoSeeded_RNG::AutoSeeded_RNG(Entropy_Sources& entropy_sources, size_t reseed_interval) {
   m_rng = std::make_unique<HMAC_DRBG>(auto_rng_hmac(), entropy_sources, reseed_interval);

   force_reseed();
}

AutoSeeded_RNG::AutoSeeded_RNG(RandomNumberGenerator& underlying_rng,
                               Entropy_Sources& entropy_sources,
                               size_t reseed_interval) {
   m_rng = std::make_unique<HMAC_DRBG>(auto_rng_hmac(), underlying_rng, entropy_sources, reseed_interval);

   force_reseed();
}

AutoSeeded_RNG::AutoSeeded_RNG(size_t reseed_interval) {
#if defined(BOTAN_HAS_SYSTEM_RNG)
   m_rng = std::make_unique<HMAC_DRBG>(auto_rng_hmac(), system_rng(), reseed_interval);
#elif defined(BOTAN_HAS_ENTROPY_SOURCE)
   m_rng = std::make_unique<HMAC_DRBG>(auto_rng_hmac(), Entropy_Sources::global_sources(), reseed_interval);
#else
   BOTAN_UNUSED(reseed_interval);
   throw Not_Implemented("AutoSeeded_RNG default constructor not available due to no RNG or entropy sources");
#endif

   force_reseed();
}

void AutoSeeded_RNG::force_reseed() {
   BOTAN_STATE_CHECK(m_rng);
   m_rng->force_reseed();
   m_rng->next_byte();
}

bool AutoSeeded_RNG::is_seeded() const {
   return m_rng && m_rng->is_seeded();
}

void AutoSeeded_RNG::clear() {
   BOTAN_STATE_CHECK(m_rng);
   m_rng->clear();
}

std::string AutoSeeded_RNG::name() const {
   BOTAN_STATE_CHECK(m_rng);
   return m_rng->name();
}

size_t AutoSeeded_RNG::reseed_from_sources(Entropy_Sources& srcs, size_t poll_bits) {
   BOTAN_STATE_CHECK(m_rng);
   return m_rng->reseed_from_sources(srcs, poll_bits);
}

void AutoSeeded_RNG::accept_seed_material(std::span<const uint8_t> input) {
   BOTAN_STATE_CHECK(m_rng);
   m_rng->add_entropy(input);
}

void AutoSeeded_RNG::fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t> in) {
   BOTAN_STATE_CHECK(m_rng);

   if(out.empty() && in.empty()) {
      return;
   } else if(in.empty()) {
      m_rng->randomize_with_ts_input(out);
   } else {
      m_rng->randomize_with_input(out, in);
   }
}

}  // namespace Botan
