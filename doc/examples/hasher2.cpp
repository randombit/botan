/*
* (C) 2001 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

/*
Identical to hasher.cpp, but uses Pipe in a different way.

Note this tends to be much less efficient than hasher.cpp, because it
does three passes over the file. For a small file, it doesn't really
matter. But for a large file, or for something you can't re-read
easily (socket, stdin, ...)  this is a bad idea.
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

   Botan::Pipe pipe;

   int skipped = 0;
   for(int j = 1; argv[j] != 0; j++)
      {
      Botan::Filter* hash[COUNT] = {
         new Botan::Hash_Filter(name[0]),
         new Botan::Hash_Filter(name[1]),
         new Botan::Hash_Filter(name[2]),
      };

      std::ifstream file(argv[j], std::ios::binary);
      if(!file)
         {
         std::cout << "ERROR: could not open " << argv[j] << std::endl;
         skipped++;
         continue;
         }
      for(int k = 0; k != COUNT; k++)
         {
         pipe.reset();
         pipe.append(hash[k]);
         pipe.append(new Botan::Hex_Encoder);
         pipe.start_msg();

         // trickiness: the >> op reads until EOF, but seekg won't work
         // unless we're in the "good" state (which EOF is not).
         file.clear();
         file.seekg(0, std::ios::beg);
         file >> pipe;
         pipe.end_msg();
         }
      file.close();
      for(int k = 0; k != COUNT; k++)
         {
         std::string out = pipe.read_all_as_string(COUNT*(j-1-skipped) + k);
         std::cout << name[k] << "(" << argv[j] << ") = " << out << std::endl;
         }
      }

   return 0;
   }
