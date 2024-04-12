/*
* Roughtime
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_ROUGHTIME)

   #include <botan/base64.h>
   #include <botan/ed25519.h>
   #include <botan/hash.h>
   #include <botan/hex.h>
   #include <botan/rng.h>
   #include <botan/roughtime.h>
   #include <botan/internal/calendar.h>

   #include <fstream>
   #include <iomanip>

namespace Botan_CLI {

class RoughtimeCheck final : public Command {
   public:
      RoughtimeCheck() : Command("roughtime_check --raw-time chain-file") {}

      std::string group() const override { return "misc"; }

      std::string description() const override { return "Parse and validate Roughtime chain file"; }

      void go() override {
         const auto chain = Botan::Roughtime::Chain(slurp_file_as_str(get_arg("chain-file")));
         unsigned i = 0;
         for(const auto& response : chain.responses()) {
            output() << std::setw(3) << ++i << ": UTC ";
            if(flag_set("raw-time")) {
               output()
                  << Botan::Roughtime::Response::sys_microseconds64(response.utc_midpoint()).time_since_epoch().count();
            } else {
               output() << Botan::calendar_point(response.utc_midpoint()).to_string();
            }
            output() << " (+-" << Botan::Roughtime::Response::microseconds32(response.utc_radius()).count() << "us)\n";
         }
      }
};

BOTAN_REGISTER_COMMAND("roughtime_check", RoughtimeCheck);

class Roughtime final : public Command {
   public:
      Roughtime() :
            Command(
               "roughtime --raw-time --chain-file=roughtime-chain --max-chain-size=128 --check-local-clock=60 --host= --pubkey= --servers-file=") {
      }

      std::string help_text() const override {
         return Command::help_text() + R"(

--servers-file=<filename>
   List of servers that will queried in sequence.

   File contents syntax:
      <name> <key type> <base 64 encoded public key> <protocol> <host:port>

   Example servers:
      Cloudflare-Roughtime ed25519 0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg= udp roughtime.cloudflare.com:2003
      Google-Sandbox-Roughtime ed25519 etPaaIxcBMY1oUeGpwvPMCJMwlRVNxv51KK/tktoJTQ= udp roughtime.sandbox.google.com:2002

--chain-file=<filename>
   Succesfull queries are appended to this file.
   If limit of --max-chain-size records is reached, the oldest records are truncated.
   This queries records can be replayed using command roughtime_check <chain-file>.

   File contents syntax:
      <key type> <base 64 encoded public key> <base 64 encoded blind or nonce> <base 64 encoded server response>
)";
      }

      std::string group() const override { return "misc"; }

      std::string description() const override { return "Retrieve time from Roughtime server"; }

      void query(std::unique_ptr<Botan::Roughtime::Chain>& chain,
                 const size_t max_chain_size,
                 const std::string& address,
                 const Botan::Ed25519_PublicKey& public_key) {
         Botan::Roughtime::Nonce nonce;
         Botan::Roughtime::Nonce blind;
         if(chain) {
            blind = Botan::Roughtime::Nonce(rng());
            nonce = chain->next_nonce(blind);
         } else {
            nonce = Botan::Roughtime::Nonce(rng());
         }
         const auto response_raw = Botan::Roughtime::online_request(address, nonce, std::chrono::seconds(5));
         const auto response = Botan::Roughtime::Response::from_bits(response_raw, nonce);
         if(flag_set("raw-time")) {
            output()
               << "UTC "
               << Botan::Roughtime::Response::sys_microseconds64(response.utc_midpoint()).time_since_epoch().count();
         } else {
            output() << "UTC " << Botan::calendar_point(response.utc_midpoint()).to_string();
         }
         output() << " (+-" << Botan::Roughtime::Response::microseconds32(response.utc_radius()).count() << "us)";
         if(!response.validate(public_key)) {
            error_output() << "ERROR: Public key does not match!\n";
            set_return_code(1);
            return;
         }
         const auto tolerance = get_arg_sz("check-local-clock");
         if(tolerance) {
            const auto now = std::chrono::system_clock::now();
            const auto diff_abs =
               now >= response.utc_midpoint() ? now - response.utc_midpoint() : response.utc_midpoint() - now;
            if(diff_abs > (response.utc_radius() + std::chrono::seconds(tolerance))) {
               error_output() << "ERROR: Local clock mismatch\n";
               set_return_code(1);
               return;
            }
            output() << " Local clock match";
         }
         if(chain) {
            chain->append({response_raw, public_key, blind}, max_chain_size);
         }
         output() << '\n';
      }

      void go() override {
         const auto max_chain_size = get_arg_sz("max-chain-size");
         const auto chain_file = get_arg("chain-file");
         const auto servers_file = get_arg_or("servers-file", "");
         const auto host = get_arg_or("host", "");
         const auto pk = get_arg_or("pubkey", "");

         std::unique_ptr<Botan::Roughtime::Chain> chain;
         if(!chain_file.empty() && max_chain_size >= 1) {
            try {
               chain = std::make_unique<Botan::Roughtime::Chain>(slurp_file_as_str(chain_file));
            } catch(const CLI_IO_Error&) {
               // file is to still be created
               chain = std::make_unique<Botan::Roughtime::Chain>();
            }
         }

         const bool from_servers_file = !servers_file.empty();
         const bool from_host_and_pk = !host.empty() && !pk.empty();
         if(from_servers_file == from_host_and_pk) {
            error_output() << "Please specify either --servers-file or --host and --pubkey\n";
            set_return_code(1);
            return;
         }

         if(!servers_file.empty()) {
            const auto servers = Botan::Roughtime::servers_from_str(slurp_file_as_str(servers_file));

            for(const auto& s : servers) {
               output() << std::setw(25) << std::left << s.name() << ": ";
               for(const auto& a : s.addresses()) {
                  try {
                     query(chain, max_chain_size, a, s.public_key());
                     break;
                  } catch(const std::exception& ex)  //network error, try next address
                  {
                     error_output() << ex.what() << '\n';
                  }
               }
            }

         } else {
            query(chain, max_chain_size, host, Botan::Ed25519_PublicKey(Botan::base64_decode(pk)));
         }

         if(chain) {
            std::ofstream out(chain_file);
            out << chain->to_string();
         }
      }
};

BOTAN_REGISTER_COMMAND("roughtime", Roughtime);

}  // namespace Botan_CLI

#endif
