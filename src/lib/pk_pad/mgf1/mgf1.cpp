/*
* MGF1
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/mgf1.h>
#include <botan/exceptn.h>
#include <algorithm>

namespace Botan {

void mgf1_mask(HashFunction& hash,
               const uint8_t in[], size_t in_len,
               uint8_t out[], size_t out_len) {
  uint32_t counter = 0;

  while (out_len) {
    hash.update(in, in_len);
    hash.update_be(counter);
    secure_vector<uint8_t> buffer = hash.final();

    size_t xored = std::min<size_t>(buffer.size(), out_len);
    xor_buf(out, buffer.data(), xored);
    out += xored;
    out_len -= xored;

    ++counter;
  }
}

}
