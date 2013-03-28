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
class Nonce_State;

/**
* OCB Mode (base class for OCB_Encryption and OCB_Decryption). Note
* that OCB is patented, but is freely licensed in some circumstances.
*
* @see "The OCB Authenticated-Encryption Algorithm" internet draft
        http://tools.ietf.org/html/draft-irtf-cfrg-ocb-00
* @see Free Licenses http://www.cs.ucdavis.edu/~rogaway/ocb/license.htm
* @see OCB home page http://www.cs.ucdavis.edu/~rogaway/ocb
*/
class BOTAN_DLL OCB_Mode : public AEAD_Mode
   {
   public:
      secure_vector<byte> start(const byte nonce[], size_t nonce_len) override;

      void set_associated_data(const byte ad[], size_t ad_len) override;

      std::string name() const override;

      size_t update_granularity() const;

      Key_Length_Specification key_spec() const override;

      bool valid_nonce_length(size_t) const override;

      void clear();

      ~OCB_Mode();
   protected:
      static const size_t BS = 16; // intrinsic to OCB definition

      /**
      * @param cipher the 128-bit block cipher to use
      * @param tag_size is how big the auth tag will be
      */
      OCB_Mode(BlockCipher* cipher, size_t tag_size);

      void key_schedule(const byte key[], size_t length) override;

      size_t tag_size() const { return m_tag_size; }

      // fixme make these private
      std::unique_ptr<BlockCipher> m_cipher;
      std::unique_ptr<L_computer> m_L;

      size_t m_tag_size = 0;
      size_t m_block_index = 0;

      secure_vector<byte> m_ad_hash;
      secure_vector<byte> m_offset;
      secure_vector<byte> m_checksum;
   private:
      std::unique_ptr<Nonce_State> m_nonce_state;
   };

class BOTAN_DLL OCB_Encryption : public OCB_Mode
   {
   public:
      /**
      * @param cipher the 128-bit block cipher to use
      * @param tag_size is how big the auth tag will be
      */
      OCB_Encryption(BlockCipher* cipher, size_t tag_size = 16) :
         OCB_Mode(cipher, tag_size) {}

      size_t minimum_final_size() const override { return 0; }

      void update(secure_vector<byte>& blocks, size_t offset) override;

      void finish(secure_vector<byte>& final_block, size_t offset) override;
   private:
      void encrypt(byte input[], size_t blocks);
   };

class BOTAN_DLL OCB_Decryption : public OCB_Mode
   {
   public:
      /**
      * @param cipher the 128-bit block cipher to use
      * @param tag_size is how big the auth tag will be
      */
      OCB_Decryption(BlockCipher* cipher, size_t tag_size = 16) :
         OCB_Mode(cipher, tag_size) {}

      size_t minimum_final_size() const override { return tag_size(); }

      void update(secure_vector<byte>& blocks, size_t offset) override;

      void finish(secure_vector<byte>& final_block, size_t offset) override;
   private:
      void decrypt(byte input[], size_t blocks);
   };

}

#endif
