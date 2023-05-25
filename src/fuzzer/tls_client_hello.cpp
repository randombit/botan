/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/tls_messages.h>

void fuzz(const uint8_t in[], size_t len) {
   try {
      std::vector<uint8_t> v(in, in + len);
      Botan::TLS::Client_Hello_12 ch(v);  // TODO: We might want to do that for TLS 1.3 as well
   } catch(Botan::Exception& e) {}
}
