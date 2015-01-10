/*
* MGF1
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/mgf1.h>
#include <botan/exceptn.h>
#include <botan/internal/xor_buf.h>
#include <algorithm>

namespace Botan {

void mgf1_mask(HashFunction& hash,
               const byte in[], size_t in_len,
               byte out[], size_t out_len)
   {
   u32bit counter = 0;

   while(out_len)
      {
      hash.update(in, in_len);
      hash.update_be(counter);
      secure_vector<byte> buffer = hash.final();

      size_t xored = std::min<size_t>(buffer.size(), out_len);
      xor_buf(out, &buffer[0], xored);
      out += xored;
      out_len -= xored;

      ++counter;
      }
   }

}
