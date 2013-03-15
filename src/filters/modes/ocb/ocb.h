/*
* OCB Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_OCB_H__
#define BOTAN_OCB_H__

#include <botan/aead.h>
#include <botan/block_cipher.h>
#include <botan/buf_filt.h>
#include <memory>

namespace Botan {

class L_computer;
//class Nonce_State;

/**
* OCB Mode (base class for OCB_Encryption and OCB_Decryption). Note
* that OCB is patented, but is freely licensed in some circumstances.
*
* @see "The OCB Authenticated-Encryption Algorithm" internet draft
        http://tools.ietf.org/html/draft-irtf-cfrg-ocb-00
* @see Free Licenses http://www.cs.ucdavis.edu/~rogaway/ocb/license.htm
* @see OCB home page http://www.cs.ucdavis.edu/~rogaway/ocb
*/
class BOTAN_DLL OCB_Mode : public AEAD_Mode,
                           private Buffered_Filter
   {
   public:
      /**
      * @param cipher the 128-bit block cipher to use
      * @param tag_size is how big the auth tag will be
      * @param decrypting  true if decrypting
      */
      OCB_Mode(BlockCipher* cipher, size_t tag_size, bool decrypting);

      ~OCB_Mode();

      void set_key(const SymmetricKey& key) override;
      void set_nonce(const byte nonce[], size_t nonce_len) override;

      void set_associated_data(const byte ad[], size_t ad_len) override;

      bool valid_keylength(size_t n) const override;

      std::string name() const override;

      bool valid_iv_length(size_t length) const override
         {
         return (length > 0 && length < 16);
         }

   protected:
      static const size_t BS = 16;

      // fixme make these private
      std::unique_ptr<BlockCipher> m_cipher;
      std::unique_ptr<L_computer> m_L;

      size_t m_tag_size = 0;
      size_t m_block_index = 0;

      secure_vector<byte> m_ad_hash;
      secure_vector<byte> m_offset;
      secure_vector<byte> m_checksum;

   private:
      void write(const byte input[], size_t input_length) override;
      void start_msg() override;
      void end_msg() override;
   };

class BOTAN_DLL OCB_Encryption : public OCB_Mode
   {
   public:
      /**
      * @param cipher the 128-bit block cipher to use
      * @param tag_size is how big the auth tag will be
      */
      OCB_Encryption(BlockCipher* cipher, size_t tag_size = 16) :
         OCB_Mode(cipher, tag_size, false) {}

   private:
      void buffered_block(const byte input[], size_t input_length) override;
      void buffered_final(const byte input[], size_t input_length) override;
   };

class BOTAN_DLL OCB_Decryption : public OCB_Mode
   {
   public:
      /**
      * @param cipher the 128-bit block cipher to use
      * @param tag_size is how big the auth tag will be
      */
      OCB_Decryption(BlockCipher* cipher, size_t tag_size = 16) :
         OCB_Mode(cipher, tag_size, true) {}

   private:
      void buffered_block(const byte input[], size_t input_length) override;
      void buffered_final(const byte input[], size_t input_length) override;
   };

}

#endif
