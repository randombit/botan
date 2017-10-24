/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"
#include <botan/rng.h>
#include <botan/entropy_src.h>
#include <botan/cpuid.h>
#include <botan/hex.h>

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   #include <botan/auto_rng.h>
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
   #include <botan/system_rng.h>
#endif

#if defined(BOTAN_HAS_RDRAND_RNG)
   #include <botan/rdrand_rng.h>
#endif

#if defined(BOTAN_HAS_HMAC_DRBG)
   #include <botan/hmac_drbg.h>
#endif

namespace Botan_CLI {

std::unique_ptr<Botan::RandomNumberGenerator>
cli_make_rng(const std::string& rng_type, const std::string& hex_drbg_seed)
   {
#if defined(BOTAN_HAS_SYSTEM_RNG)
   if(rng_type == "system" || rng_type.empty())
      {
      return std::unique_ptr<Botan::RandomNumberGenerator>(new Botan::System_RNG);
      }
#endif

#if defined(BOTAN_HAS_RDRAND_RNG)
   if(rng_type == "rdrand")
      {
      if(Botan::CPUID::has_rdrand())
         return std::unique_ptr<Botan::RandomNumberGenerator>(new Botan::RDRAND_RNG);
      else
         throw CLI_Error("RDRAND instruction not supported on this processor");
      }
#endif

   const std::vector<uint8_t> drbg_seed = Botan::hex_decode(hex_drbg_seed);

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   if(rng_type == "auto" || rng_type == "entropy" || rng_type.empty())
      {
      std::unique_ptr<Botan::RandomNumberGenerator> rng;

      if(rng_type == "entropy")
         rng.reset(new Botan::AutoSeeded_RNG(Botan::Entropy_Sources::global_sources()));
      else
         rng.reset(new Botan::AutoSeeded_RNG);

      if(drbg_seed.size() > 0)
         rng->add_entropy(drbg_seed.data(), drbg_seed.size());
      return rng;
      }
#endif

#if defined(BOTAN_HAS_HMAC_DRBG) && defined(BOTAN_AUTO_RNG_HMAC)
   if(rng_type == "drbg")
      {
      std::unique_ptr<Botan::MessageAuthenticationCode> mac =
         Botan::MessageAuthenticationCode::create(BOTAN_AUTO_RNG_HMAC);
      std::unique_ptr<Botan::Stateful_RNG> rng(new Botan::HMAC_DRBG(std::move(mac)));
      rng->add_entropy(drbg_seed.data(), drbg_seed.size());

      if(rng->is_seeded() == false)
         throw CLI_Error("For " + rng->name() + " a seed of at least " +
                         std::to_string(rng->security_level()/8) +
                         " bytes must be provided");

      return std::unique_ptr<Botan::RandomNumberGenerator>(rng.release());
      }
#endif

   throw CLI_Error_Unsupported("RNG", rng_type);
   }

}
