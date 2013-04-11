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
      * Returns the size of the output if this mode is used to process
      * a message with input_length bytes. Typically this will be
      * input_length plus or minus the length of the tag.
      */
      virtual size_t output_length(size_t input_length) const = 0;

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
      * @return Random nonce appropriate for passing to start
      */
      //virtual secure_vector<byte> nonce(RandomNumberGenerator& rng) const = 0;

      /**
      * Set associated data that is not included in the ciphertext but
      * that should be authenticated. Must be called after set_key
      * and before finish.
      *
      * Unless reset by another call, the associated data is kept
      * between messages. Thus, if the AD does not change, calling
      * once (after set_key) is the optimum.
      *
      * @param ad the associated data
      * @param ad_len length of add in bytes
      */
      virtual void set_associated_data(const byte ad[], size_t ad_len) = 0;

      template<typename Alloc>
      void set_associated_data_vec(const std::vector<byte, Alloc>& ad)
         {
         set_associated_data(&ad[0], ad.size());
         }

      virtual bool valid_nonce_length(size_t) const = 0;

      /**
      * Begin processing a message.
      *
      * @param nonce the per message nonce
      * @param nonce_len length of nonce
      */
      virtual secure_vector<byte> start(const byte nonce[], size_t nonce_len) = 0;

      template<typename Alloc>
      secure_vector<byte> start_vec(const std::vector<byte, Alloc>& nonce)
         {
         return start(&nonce[0], nonce.size());
         }

      /**
      * Update (encrypt or decrypt) some data. Input must be in size
      * update_granularity() byte blocks.
      * @param blocks in/out paramter which will possibly be resized
      */
      virtual void update(secure_vector<byte>& blocks, size_t offset = 0) = 0;

      /**
      * Complete processing of a message. For decryption, may throw an exception
      * due to authentication failure.
      *
      * @param final_block in/out parameter which must be at least
      *        minimum_final_size() bytes, and will be set to any final output
      * @param offset an offset into final_block to begin processing
      */
      virtual void finish(secure_vector<byte>& final_block, size_t offset = 0) = 0;

      virtual ~AEAD_Mode() {}
   };

/**
* Get an AEAD mode by name (eg "AES-128/GCM" or "Serpent/EAX")
*/
BOTAN_DLL AEAD_Mode* get_aead(const std::string& name, Cipher_Dir direction);

}

#endif
