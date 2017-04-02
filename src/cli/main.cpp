/*
* (C) 2009,2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#include <botan/version.h>
#include <botan/internal/stl_util.h>
#include <iterator>
#include <sstream>

namespace {

std::string main_help()
   {
   const std::set<std::string> avail_commands =
      Botan::map_keys_as_set(Botan_CLI::Command::global_registry());

   std::ostringstream oss;

   oss << "Usage: botan <cmd> <cmd-options>\n";
   oss << "Available commands:\n";

   for(auto& cmd_name : avail_commands)
      {
      auto cmd = Botan_CLI::Command::get_cmd(cmd_name);
      oss << cmd->cmd_spec() << "\n";
      }

   return oss.str();
   }

}

int main(int argc, char* argv[])
   {
   std::cerr << Botan::runtime_version_check(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH);

   const std::string cmd_name = (argc <= 1) ? "help" : argv[1];

   if(cmd_name == "help" || cmd_name == "--help" || cmd_name == "-h")
      {
      std::cout << main_help();
      return 1;
      }

   std::unique_ptr<Botan_CLI::Command> cmd(Botan_CLI::Command::get_cmd(cmd_name));

   if(!cmd)
      {
      std::cout << "Unknown command " << cmd_name << " (try --help)\n";
      return 1;
      }

   std::vector<std::string> args(argv + 2, argv + argc);
   return cmd->run(args);
   }
