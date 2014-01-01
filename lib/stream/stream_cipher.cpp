/*
* Stream Cipher
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/stream_cipher.h>

namespace Botan {

void StreamCipher::set_iv(const byte[], size_t iv_len)
   {
   if(iv_len)
      throw Invalid_Argument("The stream cipher " + name() +
                             " does not support resyncronization");
   }

bool StreamCipher::valid_iv_length(size_t iv_len) const
   {
   return (iv_len == 0);
   }

}
