/*
* (C) 2009,2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"
#include <botan/version.h>
#include <iostream>
#include <algorithm>

int main(int argc, char* argv[])
   {
   std::cerr << Botan::runtime_version_check(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH);

   std::string cmd_name = "help";

   if(argc >= 2)
      {
      cmd_name = argv[1];
      if(cmd_name == "--help" || cmd_name == "-h")
         cmd_name = "help";
      if(cmd_name == "--version" || cmd_name == "-V")
         cmd_name = "version";
      }

   std::unique_ptr<Botan_CLI::Command> cmd(Botan_CLI::Command::get_cmd(cmd_name));

   if(!cmd)
      {
      std::cout << "Unknown command " << cmd_name << " (try --help)\n";
      return 1;
      }

   std::vector<std::string> args(argv + std::min(argc, 2), argv + argc);
   return cmd->run(args);
   }
