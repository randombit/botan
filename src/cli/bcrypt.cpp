/*
* (C) 2009,2010,2014,2015,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_BCRYPT)
   #include <botan/bcrypt.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_BCRYPT)

class Generate_Bcrypt final : public Command
   {
   public:
      Generate_Bcrypt() : Command("gen_bcrypt --work-factor=12 password") {}

      std::string group() const override
         {
         return "passhash";
         }

      std::string description() const override
         {
         return "Calculate bcrypt password hash";
         }

      void go() override
         {
         const std::string password = get_passphrase_arg("Passphrase to hash", "password");
         const size_t wf = get_arg_sz("work-factor");

         if(wf < 4 || wf > 18)
            {
            error_output() << "Invalid bcrypt work factor\n";
            }
         else
            {
            const uint16_t wf16 = static_cast<uint16_t>(wf);
            output() << Botan::generate_bcrypt(password, rng(), wf16) << "\n";
            }
         }
   };

BOTAN_REGISTER_COMMAND("gen_bcrypt", Generate_Bcrypt);

class Check_Bcrypt final : public Command
   {
   public:
      Check_Bcrypt() : Command("check_bcrypt password hash") {}

      std::string group() const override
         {
         return "passhash";
         }

      std::string description() const override
         {
         return "Verify bcrypt password hash";
         }

      void go() override
         {
         const std::string password = get_passphrase_arg("Password to check", "password");
         const std::string hash = get_arg("hash");

         if(hash.length() != 60)
            {
            error_output() << "Note: bcrypt '" << hash << "' has wrong length and cannot be valid\n";
            }

         const bool ok = Botan::check_bcrypt(password, hash);

         output() << "Password is " << (ok ? "valid" : "NOT valid") << std::endl;

         if(ok == false)
            set_return_code(1);
         }
   };

BOTAN_REGISTER_COMMAND("check_bcrypt", Check_Bcrypt);

#endif // bcrypt

}
