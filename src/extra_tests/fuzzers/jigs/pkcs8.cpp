/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "driver.h"

#include <botan/pkcs8.h>
#include <botan/system_rng.h>

void fuzz(const uint8_t in[], size_t len)
   {
   try
      {
      System_RNG rng;
      DataSource_Memory input(in, len);
      std::unique_ptr<Private_Key> key(PKCS8::load_key(input, rng));
      }
   catch(Botan::Exception& e) { }
   }
