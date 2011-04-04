/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <fstream>
#include <iostream>
#include <string>
#include <botan/botan.h>

int main(int argc, char* argv[])
   {
   if(argc < 2)
      {
      std::cout << "Usage: " << argv[0] << " <filenames>" << std::endl;
      return 1;
      }

   Botan::LibraryInitializer init;

   const int COUNT = 3;
   std::string name[COUNT] = { "MD5", "SHA-1", "RIPEMD-160" };

   for(int j = 1; argv[j] != 0; j++)
      {
      Botan::Filter* hash[COUNT] = {
         new Botan::Chain(new Botan::Hash_Filter(name[0]),
                          new Botan::Hex_Encoder),
         new Botan::Chain(new Botan::Hash_Filter(name[1]),
                          new Botan::Hex_Encoder),
         new Botan::Chain(new Botan::Hash_Filter(name[2]),
                          new Botan::Hex_Encoder)
      };

      Botan::Pipe pipe(new Botan::Fork(hash, COUNT));

      std::ifstream file(argv[j], std::ios::binary);
      if(!file)
         {
         std::cout << "ERROR: could not open " << argv[j] << std::endl;
         continue;
         }
      pipe.start_msg();
      file >> pipe;
      pipe.end_msg();
      file.close();
      for(int k = 0; k != COUNT; k++)
         {
         pipe.set_default_msg(k);
         std::cout << name[k] << "(" << argv[j] << ") = " << pipe << std::endl;
         }
      }
   return 0;
   }
