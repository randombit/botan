/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"
#include <botan/entropy_src.h>
#include <botan/hex.h>
#include <botan/rng.h>
#include <botan/internal/parsing.h>

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   #include <botan/auto_rng.h>
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
   #include <botan/system_rng.h>
#endif

#if defined(BOTAN_HAS_PROCESSOR_RNG)
   #include <botan/processor_rng.h>
#endif

#if defined(BOTAN_HAS_HMAC_DRBG)
   #include <botan/hmac_drbg.h>
#endif

namespace Botan_CLI {

std::shared_ptr<Botan::RandomNumberGenerator> cli_make_rng(const std::string& rng_type,
                                                           const std::string& hex_drbg_seed) {
#if defined(BOTAN_HAS_SYSTEM_RNG)
   if(rng_type == "system" || rng_type.empty()) {
      return std::make_shared<Botan::System_RNG>();
   }
#endif

   const std::vector<uint8_t> drbg_seed = Botan::hex_decode(hex_drbg_seed);

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   if(rng_type == "auto" || rng_type == "entropy" || rng_type.empty()) {
      std::shared_ptr<Botan::RandomNumberGenerator> rng;

      if(rng_type == "entropy") {
         rng = std::make_shared<Botan::AutoSeeded_RNG>(Botan::Entropy_Sources::global_sources());
      } else {
         rng = std::make_shared<Botan::AutoSeeded_RNG>();
      }

      if(!drbg_seed.empty()) {
         rng->add_entropy(drbg_seed.data(), drbg_seed.size());
      }
      return rng;
   }
#endif

#if defined(BOTAN_HAS_HMAC_DRBG) && defined(BOTAN_HAS_SHA2_32)
   if(rng_type == "drbg" || (rng_type.empty() && drbg_seed.empty() == false)) {
      auto mac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
      auto rng = std::make_shared<Botan::HMAC_DRBG>(std::move(mac));
      rng->add_entropy(drbg_seed.data(), drbg_seed.size());

      if(rng->is_seeded() == false) {
         throw CLI_Error("For " + rng->name() + " a seed of at least " + std::to_string(rng->security_level() / 8) +
                         " bytes must be provided");
      }

      return rng;
   }
#endif

#if defined(BOTAN_HAS_PROCESSOR_RNG)
   if(rng_type == "rdrand" || rng_type == "cpu" || rng_type.empty()) {
      if(Botan::Processor_RNG::available()) {
         return std::make_shared<Botan::Processor_RNG>();
      } else if(rng_type.empty() == false) {
         throw CLI_Error("RNG instruction not supported on this processor");
      }
   }
#endif

   if(rng_type.empty()) {
      throw CLI_Error_Unsupported("No random number generator seems to be available in the current build");
   } else {
      throw CLI_Error_Unsupported("RNG", rng_type);
   }
}

class RNG final : public Command {
   public:
      RNG() : Command("rng --format=hex --system --rdrand --auto --entropy --drbg --drbg-seed= *bytes") {}

      std::string group() const override { return "misc"; }

      std::string description() const override { return "Sample random bytes from the specified rng"; }

      void go() override {
         const std::string format = get_arg("format");
         std::string type = get_arg("rng-type");

         if(type.empty()) {
            for(std::string flag : {"system", "rdrand", "auto", "entropy", "drbg"}) {
               if(flag_set(flag)) {
                  type = flag;
                  break;
               }
            }
         }

         const std::string drbg_seed = get_arg("drbg-seed");
         auto rng = cli_make_rng(type, drbg_seed);

         for(const std::string& req : get_arg_list("bytes")) {
            const size_t req_len = Botan::to_u32bit(req);
            const auto blob = rng->random_vec(req_len);

            if(format == "binary" || format == "raw") {
               write_output(blob);
            } else {
               output() << format_blob(format, blob) << "\n";
            }
         }
      }
};

BOTAN_REGISTER_COMMAND("rng", RNG);

}  // namespace Botan_CLI
