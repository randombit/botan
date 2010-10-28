/*
* Symmetric Key Length Specification
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_KEY_LEN_SPECIFICATION_H__
#define BOTAN_KEY_LEN_SPECIFICATION_H__

#include <botan/types.h>

namespace Botan {

class BOTAN_DLL Key_Length_Specification
   {
   public:
      Key_Length_Specification(size_t keylen) :
         min_keylen(keylen),
         max_keylen(keylen),
         keylen_mod(1)
         {
         }

      Key_Length_Specification(size_t min_k,
                               size_t max_k,
                               size_t k_mod = 1) :
         min_keylen(min_k),
         max_keylen(max_k ? max_k : min_k),
         keylen_mod(k_mod)
         {
         }

      bool valid_keylength(size_t length) const
         {
         return ((length >= min_keylen) &&
                 (length <= max_keylen) &&
                 (length % keylen_mod == 0));
         }

      size_t minimum_keylength() const
         {
         return min_keylen;
         }

      size_t maximum_keylength() const
         {
         return max_keylen;
         }

      size_t keylength_multiple() const
         {
         return keylen_mod;
         }

   private:
      size_t min_keylen, max_keylen, keylen_mod;
   };

}

#endif
