/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"
#include <botan/ocsp.h>

void fuzz(const uint8_t in[], size_t len)
   {
   try
      {
      Botan::OCSP::Response response(in, len);
      }
   catch(Botan::Exception& e) { }
   }
