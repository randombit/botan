/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_ARGON2_FMT)
   #include <botan/argon2fmt.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_ARGON2_FMT)

class Generate_Argon2 final : public Command {
   public:
      Generate_Argon2() : Command("gen_argon2 --mem=65536 --p=1 --t=1 password") {}

      std::string group() const override { return "passhash"; }

      std::string description() const override { return "Calculate Argon2 password hash"; }

      void go() override {
         const std::string password = get_passphrase_arg("Passphrase to hash", "password");
         const size_t M = get_arg_sz("mem");
         const size_t p = get_arg_sz("p");
         const size_t t = get_arg_sz("t");

         output() << Botan::argon2_generate_pwhash(password.data(), password.size(), rng(), p, M, t) << "\n";
      }
};

BOTAN_REGISTER_COMMAND("gen_argon2", Generate_Argon2);

class Check_Argon2 final : public Command {
   public:
      Check_Argon2() : Command("check_argon2 password hash") {}

      std::string group() const override { return "passhash"; }

      std::string description() const override { return "Verify Argon2 password hash"; }

      void go() override {
         const std::string password = get_passphrase_arg("Password to check", "password");
         const std::string hash = get_arg("hash");

         const bool ok = Botan::argon2_check_pwhash(password.data(), password.size(), hash);

         output() << "Password is " << (ok ? "valid" : "NOT valid") << std::endl;

         if(ok == false) {
            set_return_code(1);
         }
      }
};

BOTAN_REGISTER_COMMAND("check_argon2", Check_Argon2);

#endif  // argon2

}  // namespace Botan_CLI
