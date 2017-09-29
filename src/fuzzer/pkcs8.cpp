/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/data_src.h>

void fuzz(const uint8_t in[], size_t len)
   {
   try
      {
      Botan::DataSource_Memory input(in, len);
      Botan::Null_RNG null_rng;
      std::unique_ptr<Botan::Private_Key> key(Botan::PKCS8::load_key(input, null_rng));
      }
   catch(Botan::Exception& e) { }
   }
