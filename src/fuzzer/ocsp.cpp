/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/ocsp.h>

void fuzz(std::span<const uint8_t> in) {
   try {
      Botan::OCSP::Response response(in.data(), in.size());
   } catch(Botan::Exception& e) {}
}
