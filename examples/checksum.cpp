/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/botan.h>
#include <botan/filters.h>

#include <iostream>

using namespace Botan;

int main(int argc, char* argv[])
   {
   if(argc != 2)
      {
      std::cout << "Usage: " << argv[0] << " filename\n";
      return 1;
      }

   Botan::LibraryInitializer init;

   Pipe pipe(new Fork(
                new Chain(new Hash_Filter("CRC24"), new Hex_Encoder),
                new Chain(new Hash_Filter("CRC32"), new Hex_Encoder),
                new Chain(new Hash_Filter("Adler32"), new Hex_Encoder)
                ));

   DataSource_Stream in(argv[1]);

   pipe.process_msg(in);

   std::cout << pipe.read_all_as_string(0) << "\n";
   std::cout << pipe.read_all_as_string(1) << "\n";
   std::cout << pipe.read_all_as_string(2) << "\n";
   }
