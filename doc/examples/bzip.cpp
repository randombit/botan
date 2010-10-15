/*
* Bzip2 Compression/Decompression
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <string>
#include <cstring>
#include <vector>
#include <fstream>
#include <iostream>
#include <botan/botan.h>

/*
* If Bzip2 isn't included, we know nothing works at compile time, but
* we wait to fail at runtime. Otherwise I would get 2-3 mails a month
* about how this was failing to compile (even with an informative
* #error message explaining the situation) because bzip2 wasn't
* included in the build.
*/

#if defined(BOTAN_HAS_COMPRESSOR_BZIP2)
  #include <botan/bzip2.h>
#endif

const std::string SUFFIX = ".bz2";

int main(int argc, char* argv[])
   {
   if(argc < 2)
      {
      std::cout << "Usage: " << argv[0]
                << " [-s] [-d] [-1...9] <filenames>" << std::endl;
      return 1;
      }

   Botan::LibraryInitializer init;

   std::vector<std::string> files;
   bool decompress = false, small = false;
   int level = 9;

   for(int j = 1; argv[j] != 0; j++)
      {
      if(std::strcmp(argv[j], "-d") == 0) { decompress = true; continue; }
      if(std::strcmp(argv[j], "-s") == 0) { small = true; continue; }
      if(std::strcmp(argv[j], "-1") == 0) { level = 1; continue; }
      if(std::strcmp(argv[j], "-2") == 0) { level = 2; continue; }
      if(std::strcmp(argv[j], "-3") == 0) { level = 3; continue; }
      if(std::strcmp(argv[j], "-4") == 0) { level = 4; continue; }
      if(std::strcmp(argv[j], "-5") == 0) { level = 5; continue; }
      if(std::strcmp(argv[j], "-6") == 0) { level = 6; continue; }
      if(std::strcmp(argv[j], "-7") == 0) { level = 7; continue; }
      if(std::strcmp(argv[j], "-8") == 0) { level = 8; continue; }
      if(std::strcmp(argv[j], "-9") == 0) { level = 9; continue; }
      files.push_back(argv[j]);
      }

   try {

      Botan::Filter* bzip = 0;
#ifdef BOTAN_HAS_COMPRESSOR_BZIP2
      if(decompress)
         bzip = new Botan::Bzip_Decompression(small);
      else
         bzip = new Botan::Bzip_Compression(level);
#endif

      if(!bzip)
         {
         std::cout << "Sorry, support for bzip2 not compiled into Botan\n";
         return 1;
         }

      Botan::Pipe pipe(bzip);

      for(unsigned int j = 0; j != files.size(); j++)
         {
         std::string infile = files[j], outfile = files[j];
         if(!decompress)
            outfile = outfile += SUFFIX;
         else
            outfile = outfile.replace(outfile.find(SUFFIX),
                                      SUFFIX.length(), "");

         std::ifstream in(infile.c_str(), std::ios::binary);
         std::ofstream out(outfile.c_str(), std::ios::binary);
         if(!in)
            {
            std::cout << "ERROR: could not read " << infile << std::endl;
            continue;
            }
         if(!out)
            {
            std::cout << "ERROR: could not write " << outfile << std::endl;
            continue;
            }

         pipe.start_msg();
         in >> pipe;
         pipe.end_msg();
         pipe.set_default_msg(j);
         out << pipe;

         in.close();
         out.close();
         }
   }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      return 1;
      }
   return 0;
   }
