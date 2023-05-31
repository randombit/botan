/*
* (C) 2009,2010,2014,2015 Jack Lloyd
* (C) 2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#include <botan/hex.h>

#if defined(BOTAN_HAS_MAC)
   #include <botan/mac.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_HMAC)

class HMAC final : public Command {
   public:
      HMAC() : Command("hmac --hash=SHA-256 --buf-size=4096 --no-fsname key *files") {}

      std::string group() const override { return "hmac"; }

      std::string description() const override { return "Compute the HMAC tag of given file(s)"; }

      void go() override {
         const bool no_fsname = flag_set("no-fsname");
         const std::string hash_algo = get_arg("hash");
         std::unique_ptr<Botan::MessageAuthenticationCode> hmac =
            Botan::MessageAuthenticationCode::create("HMAC(" + hash_algo + ")");

         if(!hmac) {
            throw CLI_Error_Unsupported("HMAC", hash_algo);
         }

         hmac->set_key(slurp_file(get_arg("key")));

         const size_t buf_size = get_arg_sz("buf-size");

         std::vector<std::string> files = get_arg_list("files");
         if(files.empty()) {
            files.push_back("-");
         }  // read stdin if no arguments on command line

         for(const std::string& fsname : files) {
            try {
               auto update_hmac = [&](const uint8_t b[], size_t l) { hmac->update(b, l); };
               read_file(fsname, update_hmac, buf_size);
               output() << Botan::hex_encode(hmac->final());

               if(no_fsname == false) {
                  output() << " " << fsname;
               }

               output() << "\n";
            } catch(CLI_IO_Error& e) {
               error_output() << e.what() << "\n";
            }
         }
      }
};

BOTAN_REGISTER_COMMAND("hmac", HMAC);

#endif  // hmac

}  // namespace Botan_CLI
