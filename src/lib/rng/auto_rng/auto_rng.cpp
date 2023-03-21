/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/auto_rng.h>
#include <botan/entropy_src.h>
#include <botan/hmac_drbg.h>

#if defined(BOTAN_HAS_SYSTEM_RNG)
  #include <botan/system_rng.h>
#endif

namespace Botan {

namespace {

std::unique_ptr<MessageAuthenticationCode> auto_rng_hmac()
   {
   const std::string possible_auto_rng_hmacs[] = {
      "HMAC(SHA-512)",
      "HMAC(SHA-256)",
   };

   for(const auto& hmac: possible_auto_rng_hmacs)
      {
      if(auto mac = MessageAuthenticationCode::create_or_throw(hmac))
         return mac;
      }

   // This shouldn't happen since this module has a dependency on sha2_32
   throw Internal_Error("AutoSeeded_RNG: No usable HMAC hash found");
   }

}

AutoSeeded_RNG::~AutoSeeded_RNG() = default;

AutoSeeded_RNG::AutoSeeded_RNG(RandomNumberGenerator& underlying_rng,
                               size_t reseed_interval)
   {
   m_rng = std::make_unique<HMAC_DRBG>(
      auto_rng_hmac(),
      underlying_rng,
      reseed_interval);

   force_reseed();
   }

AutoSeeded_RNG::AutoSeeded_RNG(Entropy_Sources& entropy_sources,
                               size_t reseed_interval)
   {
   m_rng = std::make_unique<HMAC_DRBG>(
      auto_rng_hmac(),
      entropy_sources,
      reseed_interval);

   force_reseed();
   }

AutoSeeded_RNG::AutoSeeded_RNG(RandomNumberGenerator& underlying_rng,
                               Entropy_Sources& entropy_sources,
                               size_t reseed_interval)
   {
   m_rng = std::make_unique<HMAC_DRBG>(
      auto_rng_hmac(),
      underlying_rng,
      entropy_sources,
      reseed_interval);

   force_reseed();
   }

AutoSeeded_RNG::AutoSeeded_RNG(size_t reseed_interval) :
#if defined(BOTAN_HAS_SYSTEM_RNG)
   AutoSeeded_RNG(system_rng(), reseed_interval)
#else
   AutoSeeded_RNG(Entropy_Sources::global_sources(), reseed_interval)
#endif
   {
   }

void AutoSeeded_RNG::force_reseed()
   {
   m_rng->force_reseed();
   m_rng->next_byte();

   if(!m_rng->is_seeded())
      {
      throw Internal_Error("AutoSeeded_RNG reseeding failed");
      }
   }

bool AutoSeeded_RNG::is_seeded() const
   {
   return m_rng->is_seeded();
   }

void AutoSeeded_RNG::clear()
   {
   m_rng->clear();
   }

std::string AutoSeeded_RNG::name() const
   {
   return m_rng->name();
   }

void AutoSeeded_RNG::add_entropy(const uint8_t in[], size_t len)
   {
   m_rng->add_entropy(in, len);
   }

size_t AutoSeeded_RNG::reseed(Entropy_Sources& srcs,
                              size_t poll_bits,
                              std::chrono::milliseconds poll_timeout)
   {
   return m_rng->reseed(srcs, poll_bits, poll_timeout);
   }

void AutoSeeded_RNG::randomize(uint8_t output[], size_t output_len)
   {
   m_rng->randomize_with_ts_input(output, output_len);
   }

void AutoSeeded_RNG::randomize_with_input(uint8_t output[], size_t output_len,
                                          const uint8_t ad[], size_t ad_len)
   {
   m_rng->randomize_with_input(output, output_len, ad, ad_len);
   }

}
