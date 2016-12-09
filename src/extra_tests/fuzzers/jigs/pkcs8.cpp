/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "driver.h"

#include <botan/pkcs8.h>

void fuzz(const uint8_t in[], size_t len)
   {
   try
      {
      DataSource_Memory input(in, len);
      std::unique_ptr<Private_Key> key(PKCS8::load_key(input, fuzzer_rng()));
      }
   catch(Botan::Exception& e) { }
   }
