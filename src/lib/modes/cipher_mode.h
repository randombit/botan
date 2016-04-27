/*
* Cipher Modes
* (C) 2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CIPHER_MODE_H__
#define BOTAN_CIPHER_MODE_H__

#include <botan/secmem.h>
#include <botan/key_spec.h>
#include <botan/exceptn.h>
#include <botan/symkey.h>
#include <botan/scan_name.h>
#include <string>
#include <vector>

namespace Botan {

/**
* Interface for cipher modes
*/
class BOTAN_DLL Cipher_Mode
   {
   public:
      typedef SCAN_Name Spec;

      virtual ~Cipher_Mode() {}

      /**
      * Begin processing a message.
      * @param nonce the per message nonce
      */
      template<typename Alloc>
      secure_vector<byte> start(const std::vector<byte, Alloc>& nonce)
         {
         return start(nonce.data(), nonce.size());
         }

      /**
      * Begin processing a message.
      * @param nonce the per message nonce
      */
      template<typename Alloc>
      BOTAN_DEPRECATED("Use Transform::start")
      secure_vector<byte> start_vec(const std::vector<byte, Alloc>& nonce)
         {
         return start(nonce.data(), nonce.size());
         }

      /**
      * Begin processing a message.
      * @param nonce the per message nonce
      * @param nonce_len length of nonce
      */
      secure_vector<byte> start(const byte nonce[], size_t nonce_len)
         {
         return start_raw(nonce, nonce_len);
         }

      /**
      * Begin processing a message.
      */
      secure_vector<byte> start()
         {
         return start_raw(nullptr, 0);
         }

      virtual secure_vector<byte> start_raw(const byte nonce[], size_t nonce_len) = 0;

      /**
      * Process some data. Input must be in size update_granularity() byte blocks.
      * @param blocks in/out parameter which will possibly be resized
      * @param offset an offset into blocks to begin processing
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
      virtual size_t default_nonce_length() const = 0;

      /**
      * Return true iff nonce_len is a valid length for the nonce
      */
      virtual bool valid_nonce_length(size_t nonce_len) const = 0;

      /**
      * Return some short name describing the provider of this tranformation.
      * Useful in cases where multiple implementations are available (eg,
      * different implementations of AES). Default "core" is used for the
      * 'standard' implementation included in the library.
      */
      virtual std::string provider() const { return "core"; }

      virtual std::string name() const = 0;

      virtual void clear() = 0;

      /**
      * Returns true iff this mode provides authentication as well as
      * confidentiality.
      */
      virtual bool authenticated() const { return false; }

      /**
      * Return the size of the authentication tag used (in bytes)
      */
      virtual size_t tag_size() const { return 0; }

      /**
      * @return object describing limits on key size
      */
      virtual Key_Length_Specification key_spec() const = 0;

      /**
      * Check whether a given key length is valid for this algorithm.
      * @param length the key length to be checked.
      * @return true if the key length is valid.
      */
      bool valid_keylength(size_t length) const
         {
         return key_spec().valid_keylength(length);
         }

      template<typename Alloc>
      void set_key(const std::vector<byte, Alloc>& key)
         {
         set_key(key.data(), key.size());
         }

      void set_key(const SymmetricKey& key)
         {
         set_key(key.begin(), key.length());
         }

      /**
      * Set the symmetric key of this transform
      * @param key contains the key material
      * @param length in bytes of key param
      */
      void set_key(const byte key[], size_t length)
         {
         if(!valid_keylength(length))
            throw Invalid_Key_Length(name(), length);
         key_schedule(key, length);
         }

   private:
      virtual void key_schedule(const byte key[], size_t length) = 0;
   };

/**
* The two possible directions for cipher filters, determining whether they
* actually perform encryption or decryption.
*/
enum Cipher_Dir { ENCRYPTION, DECRYPTION };

BOTAN_DLL Cipher_Mode* get_cipher_mode(const std::string& algo_spec, Cipher_Dir direction);

}

#endif
