/*
Prints the message digest of files, using an arbitrary hash function
chosen by the user. This is less flexible that I might like, for example:
   ./hash sha1 some_file [or md5 or sha-1 or ripemd160 or ...]
will not work, cause the name lookup is case-sensitive. Oh well...

Written by Jack Lloyd (lloyd@randombit.net), on August 4, 2002
  - December 16, 2003: "Fixed" to accept "sha1" or "md5" as a hash name

This file is in the public domain
*/

#include <iostream>
#include <fstream>
#include <botan/botan.h>

int main(int argc, char* argv[])
   {
   if(argc < 3)
      {
      std::cout << "Usage: " << argv[0] << " digest <filenames>" << std::endl;
      return 1;
      }

   Botan::LibraryInitializer init;

   std::string hash = argv[1];
   /* a couple of special cases, kind of a crock */
   if(hash == "sha1") hash = "SHA-1";
   if(hash == "md5")  hash = "MD5";

   try {
      if(!Botan::have_hash(hash))
         {
         std::cout << "Unknown hash \"" << argv[1] << "\"" << std::endl;
         return 1;
         }

      Botan::Pipe pipe(new Botan::Hash_Filter(hash),
                       new Botan::Hex_Encoder);

      int skipped = 0;
      for(int j = 2; argv[j] != 0; j++)
         {
         std::ifstream file(argv[j]);
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
