/*
* (C) 2002 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

/*
An Botan example application showing how to use the pop and prepend
functions of Pipe. Based on the md5 example. It's output should always
be identical to such.
*/

#include <iostream>
#include <fstream>
#include <botan/botan.h>

int main(int argc, char* argv[])
   {
   if(argc < 2)
      {
      std::cout << "Usage: " << argv[0] << " <filenames>" << std::endl;
      return 1;
      }

   Botan::LibraryInitializer init;

   // this is a pretty vacuous example, but it's useful as a test
   Botan::Pipe pipe;

   // CPS == Current Pipe Status, ie what Filters are set up

   pipe.prepend(new Botan::Hash_Filter("MD5"));
   // CPS: MD5

   pipe.prepend(new Botan::Hash_Filter("RIPEMD-160"));
   // CPS: RIPEMD-160 | MD5

   pipe.prepend(new Botan::Chain(
                   new Botan::Hash_Filter("RIPEMD-160"),
                   new Botan::Hash_Filter("RIPEMD-160")));
  // CPS: (RIPEMD-160 | RIPEMD-160) | RIPEMD-160 | MD5

   pipe.pop(); // will pop everything inside the Chain as well as Chain itself
   // CPS: RIPEMD-160 | MD5

   pipe.pop(); // will get rid of the RIPEMD-160 Hash_Filter
   // CPS: MD5

   pipe.prepend(new Botan::Hash_Filter("SHA-1"));
   // CPS: SHA-1 | MD5

   pipe.append(new Botan::Hex_Encoder);
   // CPS: SHA-1 | MD5 | Hex_Encoder

   pipe.prepend(new Botan::Hash_Filter("SHA-1"));
   // CPS: SHA-1 | SHA-1 | MD5 | Hex_Encoder

   pipe.pop(); // Get rid of the Hash_Filter(SHA-1)
   pipe.pop(); // Get rid of the other Hash_Filter(SHA-1)
   // CPS: MD5 | Hex_Encoder
       // The Hex_Encoder is safe because it is at the end of the Pipe,
       // and pop() pulls off the Filter that is at the start.

   pipe.prepend(new Botan::Hash_Filter("RIPEMD-160"));
   // CPS: RIPEMD-160 | MD5 | Hex_Encoder

   pipe.pop(); // Get rid of that last prepended Hash_Filter(RIPEMD-160)
   // CPS: MD5 | Hex_Encoder

   int skipped = 0;
   for(int j = 1; argv[j] != 0; j++)
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
      file.close();
      pipe.set_default_msg(j-1-skipped);
      std::cout << pipe << "  " << argv[j] << std::endl;
      }
   return 0;
   }
