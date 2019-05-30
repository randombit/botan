/*
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_PBKDF)
   #include <botan/pwdhash.h>
   #include <botan/internal/os_utils.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_PBKDF)

class PBKDF_Tune final : public Command
   {
   public:
      PBKDF_Tune() : Command("pbkdf_tune --algo=Scrypt --max-mem=256 --output-len=32 --check *times") {}

      std::string group() const override
         {
         return "passhash";
         }

      std::string description() const override
         {
         return "Tune a PBKDF algo";
         }

      void go() override
         {
         const size_t output_len = get_arg_sz("output-len");
         const std::string algo = get_arg("algo");
         const size_t max_mem = get_arg_sz("max-mem");
         const bool check_time = flag_set("check");

         std::unique_ptr<Botan::PasswordHashFamily> pwdhash_fam =
            Botan::PasswordHashFamily::create(algo);

         if(!pwdhash_fam)
            throw CLI_Error_Unsupported("Password hashing", algo);

         for(const std::string& time : get_arg_list("times"))
            {
            std::unique_ptr<Botan::PasswordHash> pwhash;

            if(time == "default")
               {
               pwhash = pwdhash_fam->default_params();
               }
            else
               {
               size_t msec = 0;
               try
                  {
                  msec = std::stoul(time);
                  }
               catch(std::exception&)
                  {
                  throw CLI_Usage_Error("Unknown time value '" + time + "' for pbkdf_tune");
                  }

               pwhash = pwdhash_fam->tune(output_len, std::chrono::milliseconds(msec), max_mem);
               }

            output() << "For " << time << " ms selected " << pwhash->to_string();

            if(pwhash->total_memory_usage() > 0)
               {
               output() << " using " << pwhash->total_memory_usage()/(1024*1024) << " MiB";
               }

            if(check_time)
               {
               std::vector<uint8_t> outbuf(output_len);
               const uint8_t salt[8] = { 0 };

               const uint64_t start_ns = Botan::OS::get_system_timestamp_ns();
               pwhash->derive_key(outbuf.data(), outbuf.size(),
                                  "test", 4, salt, sizeof(salt));
               const uint64_t end_ns = Botan::OS::get_system_timestamp_ns();
               const uint64_t dur_ns = end_ns - start_ns;

               output() << " took " << (dur_ns / 1000000.0) << " msec to compute";
               }

            output() << "\n";
            }
         }
   };

BOTAN_REGISTER_COMMAND("pbkdf_tune", PBKDF_Tune);

#endif

}
