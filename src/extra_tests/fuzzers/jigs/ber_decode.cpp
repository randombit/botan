/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "driver.h"

#include <botan/ber_dec.h>

void fuzz(const uint8_t in[], size_t len)
   {
   if(len > 4096)
      return;

   try
      {
      DataSource_Memory input(in, len);
      BER_Decoder dec(input);

      while(dec.more_items())
         {
         BER_Object obj;
         dec.get_next(obj);
         }
      }
   catch(Botan::Exception& e) { }
   }
