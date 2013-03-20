/*
* Interface for AEAD modes
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_AEAD_MODE_H__
#define BOTAN_AEAD_MODE_H__

#include <botan/sym_algo.h>

namespace Botan {

/**
* Interface for AEAD (Authenticated Encryption with Associated Data)
* modes. These modes provide both encryption and message
* authentication, and can authenticate additional per-message data
* which is not included in the ciphertext (for instance a sequence
* number).
*/
class AEAD_Mode : public SymmetricAlgorithm
   {
   public:
      /**
      * @return size of required blocks to update
      */
      virtual size_t update_granularity() const = 0;

      /**
      * @return required minimium size to finalize() - may be any
      *         length larger than this.
      */
      virtual size_t minimum_final_size() const = 0;

      /**
      * Set associated data that is not included in the ciphertext but
      * that should be authenticated. Must be called after set_key
      * and before end_msg.
      *
      * Unless reset by another call, the associated data is kept
      * between messages. Thus, if the AD does not change, calling
      * once (after set_key) is the optimum.
      *
      * @param ad the associated data
      * @param ad_len length of add in bytes
      */
      virtual void set_associated_data(const byte ad[], size_t ad_len) = 0;

      virtual bool valid_nonce_length(size_t) const = 0;

      /**
      * Begin processing a message.
      *
      * @param nonce the per message nonce
      * @param nonce_len length of nonce
      */
      virtual secure_vector<byte> start(const byte nonce[], size_t nonce_len) = 0;

      /**
      * Update (encrypt or decrypt) some data. Input must be in size
      * update_granularity() byte blocks.
      * @param blocks in/out paramter which will possibly be resized
      */
      virtual void update(secure_vector<byte>& blocks) = 0;

      /**
      * Complete processing of a message. For decryption, may throw an exception
      * due to authentication failure.
      *
      * @param final_block in/out parameter which must be at least
      *        minimum_final_size() bytes, and will be set to any final output
      */
      virtual void finish(secure_vector<byte>& final_block) = 0;

      virtual ~AEAD_Mode() {}
   };

}

#endif
