/*
* MGF1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/mgf1.h>
#include <botan/exceptn.h>
#include <botan/internal/xor_buf.h>
#include <algorithm>
#include <memory>

namespace Botan {

/*
* MGF1 Mask Generation Function
*/
void MGF1::mask(const byte in[], size_t in_len, byte out[],
                size_t out_len) const
   {
   u32bit counter = 0;

   while(out_len)
      {
      hash->update(in, in_len);
      hash->update_be(counter);
      secure_vector<byte> buffer = hash->final();

      size_t xored = std::min<size_t>(buffer.size(), out_len);
      xor_buf(out, &buffer[0], xored);
      out += xored;
      out_len -= xored;

      ++counter;
      }
   }

/*
* MGF1 Constructor
*/
MGF1::MGF1(HashFunction* h) : hash(h)
   {
   if(!hash)
      throw Invalid_Argument("MGF1 given null hash object");
   }

/*
* MGF1 Destructor
*/
MGF1::~MGF1()
   {
   delete hash;
   }

}
