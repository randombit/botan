/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "driver.h"
#include <botan/internal/tls_messages.h>

void fuzz(const uint8_t in[], size_t len)
   {
   try
      {
      std::vector<uint8_t> v(in, in + len);
      Botan::TLS::Client_Hello ch(v);
      }
   catch(Botan::Exception& e) {}
   }
