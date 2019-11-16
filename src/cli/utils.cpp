/*
* (C) 2009,2010,2014,2015 Jack Lloyd
* (C) 2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#include <botan/version.h>
#include <botan/cpuid.h>
#include <botan/internal/stl_util.h>
#include <sstream>
#include <iomanip>

#if defined(BOTAN_HAS_HTTP_UTIL)
   #include <botan/http_util.h>
#endif

#if defined(BOTAN_HAS_UUID)
   #include <botan/uuid.h>
#endif

namespace Botan_CLI {

class Print_Help final : public Command
   {
   public:
      Print_Help() : Command("help") {}

      std::string help_text() const override
         {
         std::map<std::string, std::vector<std::unique_ptr<Command>>> grouped_commands;

         auto reg_commands = Command::registered_cmds();
         for(const auto& cmd_name : reg_commands)
            {
            auto cmd = Command::get_cmd(cmd_name);
            if(cmd)
               {
               grouped_commands[cmd->group()].push_back(std::move(cmd));
               }
            }

         const std::map<std::string, std::string> groups_description {
            { "encryption", "Encryption" },
            { "compression", "Compression" },
            { "codec", "Encoders/Decoders" },
            { "hash", "Hash Functions" },
            { "hmac", "HMAC" },
            { "info", "Informational" },
            { "numtheory", "Number Theory" },
            { "passhash", "Password Hashing" },
            { "psk", "PSK Database" },
            { "pubkey", "Public Key Cryptography" },
            { "tls", "TLS" },
            { "tss", "Secret Sharing" },
            { "x509", "X.509" },
            { "misc", "Miscellaneous" }
         };

      std::ostringstream oss;

      oss << "Usage: botan <cmd> <cmd-options>\n";
      oss << "All commands support --verbose --help --output= --error-output= --rng-type= --drbg-seed=\n\n";
      oss << "Available commands:\n\n";

      for(const auto& commands : grouped_commands)
         {
         std::string desc = commands.first;
         if(desc.empty())
            {
            continue;
            }

         oss << Botan::search_map(groups_description, desc, desc) << ":\n";
         for(auto& cmd : commands.second)
            {
            oss << "   " << std::setw(16) << std::left << cmd->cmd_name() << "   " << cmd->description() << "\n";
            }
         oss << "\n";
         }

      return oss.str();
      }

      std::string group() const override
         {
         return "";
         }

      std::string description() const override
         {
         return "Prints a help string";
         }

      void go() override
         {
         this->set_return_code(1);
         output() << help_text();
         }
   };

BOTAN_REGISTER_COMMAND("help", Print_Help);

class Has_Command final : public Command
   {
   public:
      Has_Command() : Command("has_command cmd") {}

      std::string group() const override
         {
         return "info";
         }

      std::string description() const override
         {
         return "Test if a command is available";
         }

      void go() override
         {
         const std::string cmd = get_arg("cmd");

         bool exists = false;
         for(auto registered_cmd : Command::registered_cmds())
            {
            if(cmd == registered_cmd)
               {
               exists = true;
               break;
               }
            }

         if(verbose())
            {
            output() << "Command '" << cmd << "' is "
                     << (exists ? "": "not ") << "available\n";
            }

         if(exists == false)
            this->set_return_code(1);
         }
   };

BOTAN_REGISTER_COMMAND("has_command", Has_Command);

class Config_Info final : public Command
   {
   public:
      Config_Info() : Command("config info_type") {}

      std::string help_text() const override
         {
         return "Usage: config info_type\n"
                "   prefix: Print install prefix\n"
                "   cflags: Print include params\n"
                "   ldflags: Print linker params\n"
                "   libs: Print libraries\n";
         }

      std::string group() const override
         {
         return "info";
         }

      std::string description() const override
         {
         return "Print the used prefix, cflags, ldflags or libs";
         }

      void go() override
         {
         const std::string arg = get_arg("info_type");

         if(arg == "prefix")
            {
            output() << BOTAN_INSTALL_PREFIX << "\n";
            }
         else if(arg == "cflags")
            {
            output() << "-I" << BOTAN_INSTALL_PREFIX << "/" << BOTAN_INSTALL_HEADER_DIR << "\n";
            }
         else if(arg == "ldflags")
            {
            if(*BOTAN_LINK_FLAGS)
               output() << BOTAN_LINK_FLAGS << ' ';
            output() << "-L" << BOTAN_INSTALL_LIB_DIR << "\n";
            }
         else if(arg == "libs")
            {
            output() << "-lbotan-" << Botan::version_major() << " " << BOTAN_LIB_LINK << "\n";
            }
         else
            {
            throw CLI_Usage_Error("Unknown option to botan config " + arg);
            }
         }
   };

BOTAN_REGISTER_COMMAND("config", Config_Info);

class Version_Info final : public Command
   {
   public:
      Version_Info() : Command("version --full") {}

      std::string group() const override
         {
         return "info";
         }

      std::string description() const override
         {
         return "Print version info";
         }

      void go() override
         {
         if(flag_set("full"))
            {
            output() << Botan::version_string() << "\n";
            }
         else
            {
            output() << Botan::short_version_string() << "\n";
            }
         }
   };

BOTAN_REGISTER_COMMAND("version", Version_Info);

class Print_Cpuid final : public Command
   {
   public:
      Print_Cpuid() : Command("cpuid") {}

      std::string group() const override
         {
         return "info";
         }

      std::string description() const override
         {
         return "List available processor flags (aes_ni, SIMD extensions, ...)";
         }

      void go() override
         {
         output() << "CPUID flags: " << Botan::CPUID::to_string() << "\n";
         }
   };

BOTAN_REGISTER_COMMAND("cpuid", Print_Cpuid);

#if defined(BOTAN_HAS_UUID)

class Print_UUID final : public Command
   {
   public:
      Print_UUID() : Command("uuid") {}

      std::string group() const override
         {
         return "misc";
         }

      std::string description() const override
         {
         return "Print a random UUID";
         }

      void go() override
         {
         Botan::UUID uuid(rng());
         output() << uuid.to_string() << "\n";
         }
   };

BOTAN_REGISTER_COMMAND("uuid", Print_UUID);

#endif

#if defined(BOTAN_HAS_HTTP_UTIL)

class HTTP_Get final : public Command
   {
   public:
      HTTP_Get() : Command("http_get --redirects=1 --timeout=3000 url") {}

      std::string group() const override
         {
         return "misc";
         }

      std::string description() const override
         {
         return "Retrieve resource from the passed http/https url";
         }

      void go() override
         {
         const std::string url = get_arg("url");
         const std::chrono::milliseconds timeout(get_arg_sz("timeout"));
         const size_t redirects = get_arg_sz("redirects");

         output() << Botan::HTTP::GET_sync(url, redirects, timeout) << "\n";
         }
   };

BOTAN_REGISTER_COMMAND("http_get", HTTP_Get);

#endif // http_util

}
