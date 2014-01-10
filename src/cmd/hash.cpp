/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include "apps.h"
#include <botan/lookup.h>
#include <iostream>
#include <fstream>

using namespace Botan;

int hash_main(int argc, char* argv[])
   {
   if(argc < 3)
      {
      std::cout << "Usage: " << argv[0] << " digest <filenames>" << std::endl;
      return 1;
      }

   std::string hash = argv[1];
   /* a couple of special cases, kind of a crock */
   if(hash == "sha1") hash = "SHA-1";
   if(hash == "md5")  hash = "MD5";

   try {
      if(!have_hash(hash))
         {
         std::cout << "Unknown hash \"" << argv[1] << "\"" << std::endl;
         return 1;
         }

      Pipe pipe(new Hash_Filter(hash), new Hex_Encoder);

      int skipped = 0;
      for(int j = 2; argv[j] != nullptr; j++)
         {
         std::ifstream file(argv[j], std::ios::binary);
         if(!file)
            {
            std::cout << "ERROR: could not open " << argv[j] << std::endl;
            skipped++;
            continue;
            }
         pipe.start_msg();
         file >> pipe;
         pipe.end_msg();
         pipe.set_default_msg(j-2-skipped);
         std::cout << pipe << "  " << argv[j] << std::endl;
         }
   }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      }
   return 0;
   }
