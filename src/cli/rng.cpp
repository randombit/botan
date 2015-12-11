/*
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"
#include <botan/entropy_src.h>
#include <botan/auto_rng.h>

#if defined(BOTAN_HAS_SYSTEM_RNG)
  #include <botan/system_rng.h>
#endif

namespace {

int rng(const std::vector<std::string> &args)
   {
   if(args.size() < 2 || args.size() > 3)
      {
      std::cout << "Usage: " << args[0] << " [--raw-entropy] n\n"
                << "n: number of bytes"
                << std::endl;
      return 1;
      }

   try
      {
      const size_t bytes_count = to_u32bit(args.back());
      const bool raw = (args.size() == 3 && args[1] == "--raw-entropy");

#if defined(BOTAN_HAS_SYSTEM_RNG)
      std::cout << "System " << hex_encode(system_rng().random_vec(bytes_count)) << std::endl;
#endif

      if(!raw)
         {
         AutoSeeded_RNG rng;
         std::cout << hex_encode(rng.random_vec(bytes_count)) << std::endl;
         }
      else
         {
         double total_collected = 0;

         Entropy_Accumulator accum(
            [bytes_count,&total_collected](const byte in[], size_t in_len, double entropy_estimate)
            {
            std::cout << "Collected estimated "<< entropy_estimate << " bits in "
                      << hex_encode(in, in_len) << std::endl;
            total_collected += entropy_estimate;
            return total_collected >= bytes_count;
            });

         Entropy_Sources::global_sources().poll(accum);
         }
      }
   catch(std::exception& e)
      {
      std::cout << "Error: " << e.what() << std::endl;
      return 1;
      }

   return 0;
   }

REGISTER_APP(rng);

}
