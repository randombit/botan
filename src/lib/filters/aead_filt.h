/*
* Filter interface for AEAD Modes
* (C) 2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AEAD_FILTER_H__
#define BOTAN_AEAD_FILTER_H__

#include <botan/cipher_filter.h>
#include <botan/aead.h>

namespace Botan {

/**
* Filter interface for AEAD Modes
*/
class AEAD_Filter : public Cipher_Mode_Filter
   {
   public:
      AEAD_Filter(AEAD_Mode* aead) : Cipher_Mode_Filter(aead) {}

      /**
      * Set associated data that is not included in the ciphertext but
      * that should be authenticated. Must be called after set_key
      * and before end_msg.
      *
      * @param ad the associated data
      * @param ad_len length of add in bytes
      */
      void set_associated_data(const byte ad[], size_t ad_len)
         {
         dynamic_cast<AEAD_Mode&>(get_transform()).set_associated_data(ad, ad_len);
         }
   };

}

#endif
