/*
* (C) 2009,2010,2014,2015 Jack Lloyd
* (C) 2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#include <botan/version.h>
#include <botan/internal/cpuid.h>
#include <botan/internal/os_utils.h>
#include <botan/internal/stl_util.h>
#include <iomanip>
#include <sstream>

#if defined(BOTAN_HAS_HTTP_UTIL)
   #include <botan/internal/http_util.h>
#endif

#if defined(BOTAN_HAS_UUID)
   #include <botan/uuid.h>
#endif

namespace Botan_CLI {

class Print_Help final : public Command {
   public:
      Print_Help() : Command("help") {}

      std::string help_text() const override {
         std::map<std::string, std::vector<std::unique_ptr<Command>>> grouped_commands;

         auto reg_commands = Command::registered_cmds();
         for(const auto& cmd_name : reg_commands) {
            auto cmd = Command::get_cmd(cmd_name);
            if(cmd) {
               grouped_commands[cmd->group()].push_back(std::move(cmd));
            }
         }

         const std::map<std::string, std::string> groups_description{{"codec", "Encoders/Decoders"},
                                                                     {"compression", "Compression"},
                                                                     {
                                                                        "crypto",
                                                                        "Encryption",
                                                                     },
                                                                     {"fec", "Forward Error Correction"},
                                                                     {"hash", "Hash Functions"},
                                                                     {"hmac", "HMAC"},
                                                                     {"info", "Informational"},
                                                                     {"misc", "Miscellaneous"},
                                                                     {"numtheory", "Number Theory"},
                                                                     {"passhash", "Password Hashing"},
                                                                     {"psk", "PSK Database"},
                                                                     {"pubkey", "Public Key Cryptography"},
                                                                     {"testing", "Testing"},
                                                                     {"tls", "TLS"},
                                                                     {"tss", "Secret Sharing"},
                                                                     {"x509", "X.509"}};

         std::ostringstream oss;

         oss << "Usage: botan <cmd> <cmd-options>\n";
         oss << "All commands support --verbose --help --output= --error-output= --rng-type= --drbg-seed=\n\n";
         oss << "Available commands:\n\n";

         for(const auto& commands : grouped_commands) {
            const std::string group = commands.first;
            if(group.empty()) {
               // ???
               continue;
            }

            auto descr = groups_description.find(group);
            if(descr != groups_description.end()) {
               oss << descr->second;
            } else {
               oss << group;
            }
            oss << ":\n";
            for(const auto& cmd : commands.second) {
               oss << "   " << std::setw(16) << std::left << cmd->cmd_name() << "   " << cmd->description() << "\n";
            }
            oss << "\n";
         }

         return oss.str();
      }

      std::string group() const override { return ""; }

      std::string description() const override { return "Prints a help string"; }

      void go() override {
         this->set_return_code(1);
         output() << help_text();
      }
};

BOTAN_REGISTER_COMMAND("help", Print_Help);

class Has_Command final : public Command {
   public:
      Has_Command() : Command("has_command cmd") {}

      std::string group() const override { return "info"; }

      std::string description() const override { return "Test if a command is available"; }

      void go() override {
         const std::string cmd = get_arg("cmd");

         bool exists = false;
         for(const auto& registered_cmd : Command::registered_cmds()) {
            if(cmd == registered_cmd) {
               exists = true;
               break;
            }
         }

         if(verbose()) {
            output() << "Command '" << cmd << "' is " << (exists ? "" : "not ") << "available\n";
         }

         if(exists == false) {
            this->set_return_code(1);
         }
      }
};

BOTAN_REGISTER_COMMAND("has_command", Has_Command);

class Config_Info final : public Command {
   public:
      Config_Info() : Command("config info_type") {}

      std::string help_text() const override {
         return "Usage: config info_type\n"
                "   prefix: Print install prefix\n"
                "   cflags: Print include params\n"
                "   ldflags: Print linker params\n"
                "   libs: Print libraries\n";
      }

      std::string group() const override { return "info"; }

      std::string description() const override { return "Print the used prefix, cflags, ldflags or libs"; }

      void go() override {
         const std::string arg = get_arg("info_type");

         if(arg == "prefix") {
            output() << BOTAN_INSTALL_PREFIX << "\n";
         } else if(arg == "cflags") {
            output() << "-I" << BOTAN_INSTALL_PREFIX << "/" << BOTAN_INSTALL_HEADER_DIR << "\n";
         } else if(arg == "ldflags") {
            if(*BOTAN_LINK_FLAGS) {
               output() << BOTAN_LINK_FLAGS << ' ';
            }
            output() << "-L" << BOTAN_INSTALL_LIB_DIR << "\n";
         } else if(arg == "libs") {
            output() << "-lbotan-" << Botan::version_major() << " " << BOTAN_LIB_LINK << "\n";
         } else {
            throw CLI_Usage_Error("Unknown option to botan config " + arg);
         }
      }
};

BOTAN_REGISTER_COMMAND("config", Config_Info);

class Version_Info final : public Command {
   public:
      Version_Info() : Command("version --full") {}

      std::string group() const override { return "info"; }

      std::string description() const override { return "Print version info"; }

      void go() override {
         if(flag_set("full")) {
            output() << Botan::version_string() << "\n";
         } else {
            output() << Botan::short_version_string() << "\n";
         }
      }
};

BOTAN_REGISTER_COMMAND("version", Version_Info);

class Print_Cpuid final : public Command {
   public:
      Print_Cpuid() : Command("cpuid") {}

      std::string group() const override { return "info"; }

      std::string description() const override {
         return "List available processor flags (aes_ni, SIMD extensions, ...)";
      }

      void go() override { output() << "CPUID flags: " << Botan::CPUID::to_string() << "\n"; }
};

BOTAN_REGISTER_COMMAND("cpuid", Print_Cpuid);

class Cycle_Counter final : public Command {
   public:
      Cycle_Counter() : Command("cpu_clock --test-duration=500") {}

      std::string group() const override { return "info"; }

      std::string description() const override { return "Estimate the speed of the CPU cycle counter"; }

      void go() override {
         if(Botan::OS::get_cpu_cycle_counter() == 0) {
            output() << "No CPU cycle counter on this machine\n";
            return;
         }

         const uint64_t test_duration_ns = get_arg_sz("test-duration") * 1000000;

         if(test_duration_ns == 0) {
            output() << "Invalid test duration\n";
            return;
         }

         const uint64_t cc_start = Botan::OS::get_cpu_cycle_counter();
         const uint64_t ns_start = Botan::OS::get_system_timestamp_ns();

         uint64_t cc_end = 0;
         uint64_t ns_end = ns_start;

         while((ns_end - ns_start) < test_duration_ns) {
            ns_end = Botan::OS::get_system_timestamp_ns();
            cc_end = Botan::OS::get_cpu_cycle_counter();
         }

         if(cc_end <= cc_start) {
            output() << "Cycle counter seems to have wrapped, try again\n";
            return;
         }

         if(ns_end <= ns_start) {
            output() << "System clock seems to have wrapped (?!?)\n";
            return;
         }

         const uint64_t ns_duration = ns_end - ns_start;
         const uint64_t cc_duration = cc_end - cc_start;

         const double ratio = static_cast<double>(cc_duration) / ns_duration;

         if(ratio >= 1.0) {
            // GHz
            output() << "Estimated CPU clock " << std::setprecision(2) << ratio << " GHz\n";
         } else {
            // MHz
            output() << "Estimated CPU clock " << static_cast<size_t>(ratio * 1000) << " MHz\n";
         }
      }
};

BOTAN_REGISTER_COMMAND("cpu_clock", Cycle_Counter);

#if defined(BOTAN_HAS_UUID)

class Print_UUID final : public Command {
   public:
      Print_UUID() : Command("uuid") {}

      std::string group() const override { return "misc"; }

      std::string description() const override { return "Print a random UUID"; }

      void go() override {
         Botan::UUID uuid(rng());
         output() << uuid.to_string() << "\n";
      }
};

BOTAN_REGISTER_COMMAND("uuid", Print_UUID);

#endif

#if defined(BOTAN_HAS_HTTP_UTIL)

class HTTP_Get final : public Command {
   public:
      HTTP_Get() : Command("http_get --redirects=1 --timeout=3000 url") {}

      std::string group() const override { return "misc"; }

      std::string description() const override { return "Retrieve resource from the passed http/https url"; }

      void go() override {
         const std::string url = get_arg("url");
         const std::chrono::milliseconds timeout(get_arg_sz("timeout"));
         const size_t redirects = get_arg_sz("redirects");

         output() << Botan::HTTP::GET_sync(url, redirects, timeout) << "\n";
      }
};

BOTAN_REGISTER_COMMAND("http_get", HTTP_Get);

#endif  // http_util

}  // namespace Botan_CLI
