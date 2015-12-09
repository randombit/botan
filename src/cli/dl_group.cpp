/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_DL_GROUP)

#include <botan/dl_group.h>
#include <fstream>

namespace {

std::string read_file_contents(const std::string& filename)
   {
   std::ifstream in(filename.c_str());
   if(!in.good())
      throw std::runtime_error("Failure reading " + filename);

   std::vector<std::string> contents;
   size_t total_size = 0;
   while(in.good())
      {
      std::string line;
      std::getline(in, line);
      total_size += line.size();
      contents.push_back(std::move(line));
      }

   std::string res;
   contents.reserve(total_size);
   for(auto&& line : contents)
      res += line;
   return res;
   }

int dl_group(const std::vector<std::string> &args)
   {
   if(args.size() < 2)
      {
      std::cout << "Usage: " << args[0] << " [create bits|info file]" << std::endl;
      return 1;
      }

   const std::string cmd = args[1];

   if(cmd == "create")
      {
      AutoSeeded_RNG rng;
      const size_t bits = to_u32bit(args[2]);

      const DL_Group::PrimeType prime_type = DL_Group::Strong;
      //const DL_Group::PrimeType prime_type = DL_Group::Prime_Subgroup;

      DL_Group grp(rng, prime_type, bits);

      std::cout << grp.PEM_encode(DL_Group::DSA_PARAMETERS);
      }
   else if(cmd == "info")
      {
      DL_Group grp;
      std::string pem = read_file_contents(args[2]);
      std::cout << pem << "\n";

      std::cout << "DL_Group " << grp.get_p().bits() << " bits\n";
      std::cout << "p=" << grp.get_p() << "\n";
      std::cout << "q=" << grp.get_q() << "\n";
      std::cout << "g=" << grp.get_g() << "\n";
      }
   else
      {
      std::cout << "ERROR: Unknown command\n";
      return 1;
      }

   return 0;
   }

REGISTER_APP(dl_group);

}

#endif
