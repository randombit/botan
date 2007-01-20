/*************************************************
* File EntropySource Source File                 *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/es_file.h>
#include <botan/config.h>
#include <fstream>

namespace Botan {

/*************************************************
* Gather Entropy from Randomness Source          *
*************************************************/
u32bit File_EntropySource::slow_poll(byte output[], u32bit length)
   {
   std::vector<std::string> sources =
      global_config().option_as_list("rng/es_files");

   u32bit read = 0;
   for(u32bit j = 0; j != sources.size(); ++j)
      {
      std::ifstream random_source(sources[j].c_str(), std::ios::binary);
      if(!random_source) continue;
      random_source.read((char*)output + read, length);
      read += random_source.gcount();
      length -= random_source.gcount();
      if(length == 0)
         break;
      }
   return read;
   }

}
