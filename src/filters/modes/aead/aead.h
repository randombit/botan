/*
* Interface for AEAD modes
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_AEAD_H__
#define BOTAN_AEAD_H__

#include <botan/key_filt.h>

namespace Botan {

class AEAD_Mode : public Keyed_Filter
   {
   public:
      /**
      * Set associated data that is not included in the ciphertext but
      * that should be authenticated. Must be called after set_key
      * and before end_msg.
      *
      * @param ad the associated data
      * @param ad_len length of add in bytes
      */
      virtual void set_associated_data(const byte ad[], size_t ad_len) = 0;

      virtual void set_nonce(const byte nonce[], size_t nonce_len) = 0;

      void set_iv(const InitializationVector& iv) override
         {
         set_nonce(iv.begin(), iv.length());
         }
   };

}

#endif
