/*
* CBC mode
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MODE_CBC_H__
#define BOTAN_MODE_CBC_H__

#include <botan/transform.h>
#include <botan/block_cipher.h>
#include <botan/mode_pad.h>
#include <memory>

namespace Botan {

/**
* CBC Mode
*/
class CBC_Mode : public Transformation
   {
   public:
      secure_vector<byte> start(const byte nonce[], size_t nonce_len) override;

      std::string name() const override;

      size_t update_granularity() const override;

      Key_Length_Specification key_spec() const override;

      size_t default_nonce_size() const override;

      bool valid_nonce_length(size_t n) const override;

      void clear();
   protected:
      CBC_Mode(BlockCipher* cipher, BlockCipherModePaddingMethod* padding);

      const BlockCipher& cipher() const { return *m_cipher; }

      const BlockCipherModePaddingMethod& padding() const { return *m_padding; }

      secure_vector<byte>& state() { return m_state; }

      byte* state_ptr() { return &m_state[0]; }

   private:
      void key_schedule(const byte key[], size_t length) override;

      std::unique_ptr<BlockCipher> m_cipher;
      std::unique_ptr<BlockCipherModePaddingMethod> m_padding;
      secure_vector<byte> m_state;
   };

/**
* CBC Encryption
*/
class BOTAN_DLL CBC_Encryption : public CBC_Mode
   {
   public:
      CBC_Encryption(BlockCipher* cipher, BlockCipherModePaddingMethod* padding) :
         CBC_Mode(cipher, padding) {}

      void update(secure_vector<byte>& blocks, size_t offset) override;

      void finish(secure_vector<byte>& final_block, size_t offset) override;

      size_t output_length(size_t input_length) const override;

      size_t minimum_final_size() const override;
   };

/**
* CBC Decryption
*/
class BOTAN_DLL CBC_Decryption : public CBC_Mode
   {
   public:
      CBC_Decryption(BlockCipher* cipher, BlockCipherModePaddingMethod* padding) :
         CBC_Mode(cipher, padding), m_tempbuf(update_granularity()) {}

      void update(secure_vector<byte>& blocks, size_t offset) override;

      void finish(secure_vector<byte>& final_block, size_t offset) override;

      size_t output_length(size_t input_length) const override;

      size_t minimum_final_size() const override;
   private:
      secure_vector<byte> m_tempbuf;
   };

}

#endif
