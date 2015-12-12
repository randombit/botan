/*
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_CODEC_FILTERS)

#include <botan/filters.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

int hash(const std::vector<std::string> &args)
   {
   if(args.size() < 3)
      {
      std::cout << "Usage: " << args[0] << " algorithm filename [filename ...]" << std::endl;
      return 1;
      }

   std::string hash = args[1];
   /* a couple of special cases, kind of a crock */
   if(hash == "sha1") hash = "SHA-1";
   if(hash == "md5")  hash = "MD5";

   try {
      Pipe pipe(new Hash_Filter(hash), new Hex_Encoder);

      int skipped = 0;
      for(int j = 2; j < args.size(); j++)
         {
         std::ifstream file(args[j], std::ios::binary);
         if(!file)
            {
            std::cout << "ERROR: could not open " << args[j] << std::endl;
            skipped++;
            continue;
            }
         pipe.start_msg();
         file >> pipe;
         pipe.end_msg();
         pipe.set_default_msg(j-2-skipped);
         std::cout << pipe << "  " << args[j] << std::endl;
         }
   }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      }
   return 0;
   }

REGISTER_APP(hash);

}

#endif // BOTAN_HAS_CODEC_FILTERS
