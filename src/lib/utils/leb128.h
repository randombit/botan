/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_LEB128_H_
#define BOTAN_LEB128_H_

#include <botan/types.h>
#include <vector>

namespace Botan {

void leb128_encode(size_t len, std::vector<uint8_t>& out) {
   while(len > 0) {
      const uint8_t next = static_cast<uint8_t>(len & 0x7F);
      if(len < 128) {
         out.push(next);
      } else {
         out.push(next | 0x80);
      }
      len >>= 7;
   }
}

}
