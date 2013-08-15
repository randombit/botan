/*
* Transformations of data
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TRANSFORM_H__
#define BOTAN_TRANSFORM_H__

#include <botan/sym_algo.h>

namespace Botan {

/**
* Interface for general transformations on data
*/
class Transformation : public SymmetricAlgorithm
   {
   public:
      /**
      * Begin processing a message.
      * @param nonce the per message nonce
      */
      template<typename Alloc>
      secure_vector<byte> start_vec(const std::vector<byte, Alloc>& nonce)
         {
         return start(&nonce[0], nonce.size());
         }

      /**
      * Begin processing a message.
      * @param nonce the per message nonce
      * @param nonce_len length of nonce
      */
      virtual secure_vector<byte> start(const byte nonce[], size_t nonce_len) = 0;

      /**
      * Process some data. Input must be in size update_granularity() byte blocks.
      * @param blocks in/out paramter which will possibly be resized
      */
      virtual void update(secure_vector<byte>& blocks, size_t offset = 0) = 0;

      /**
      * Complete processing of a message.
      *
      * @param final_block in/out parameter which must be at least
      *        minimum_final_size() bytes, and will be set to any final output
      * @param offset an offset into final_block to begin processing
      */
      virtual void finish(secure_vector<byte>& final_block, size_t offset = 0) = 0;

      /**
      * Returns the size of the output if this transform is used to process a
      * message with input_length bytes. Will throw if unable to give a precise
      * answer.
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
      * Return the default size for a nonce
      */
      virtual size_t default_nonce_size() const = 0;

      /**
      * Return true iff nonce_len is a valid length for the nonce
      */
      virtual bool valid_nonce_length(size_t nonce_len) const = 0;

      virtual ~Transformation() {}
   };

}

#endif
