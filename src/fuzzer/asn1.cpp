/*
* (C) 2016,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"
#include <botan/ber_dec.h>

void fuzz(const uint8_t in[], size_t len)
   {
   try
      {
      Botan::DataSource_Memory input(in, len);
      Botan::BER_Decoder dec(input);

      while(dec.more_items())
         {
         Botan::BER_Object obj;
         dec.get_next(obj);
         }
      }
   catch(Botan::Exception& e) { }
   }
