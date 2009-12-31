/*
* Encode/decode base64 strings
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <botan/botan.h>

int main(int argc, char* argv[])
   {
   if(argc < 2)
      {
      std::cout << "Usage: " << argv[0] << " [-w] [-c n] [-e|-d] files...\n"
                   "   -e  : Encode input to base64 strings (default) \n"
                   "   -d  : Decode base64 input\n"
                   "   -w  : Wrap lines\n"
                   "   -c n: Wrap lines at column n, default 78\n";
      return 1;
      }

   Botan::LibraryInitializer init;

   int column = 78;
   bool wrap = false;
   bool encoding = true;
   std::vector<std::string> files;

   for(int j = 1; argv[j] != 0; j++)
      {
      std::string this_arg = argv[j];

      if(this_arg == "-w")
         wrap = true;
      else if(this_arg == "-e");
      else if(this_arg == "-d")
         encoding = false;
      else if(this_arg == "-c")
         {
         if(argv[j+1])
            { column = atoi(argv[j+1]); j++; }
         else
            {
            std::cout << "No argument for -c option" << std::endl;
            return 1;
            }
         }
      else files.push_back(argv[j]);
      }

   for(unsigned int j = 0; j != files.size(); j++)
      {
      std::istream* stream;
      if(files[j] == "-") stream = &std::cin;
      else                stream = new std::ifstream(files[j].c_str());

      if(!*stream)
         {
         std::cout << "ERROR, couldn't open " << files[j] << std::endl;
         continue;
         }

      Botan::Pipe pipe((encoding) ?
                   ((Botan::Filter*)new Botan::Base64_Encoder(wrap, column)) :
                   ((Botan::Filter*)new Botan::Base64_Decoder));
      pipe.start_msg();
      *stream >> pipe;
      pipe.end_msg();
      pipe.set_default_msg(j);
      std::cout << pipe;
      if(files[j] != "-") delete stream;
      }
   return 0;
   }
