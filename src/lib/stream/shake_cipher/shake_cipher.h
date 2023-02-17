/*
 * SHAKE-128 and SHAKE-256 as a stream ciphers
 * (C) 2016 Jack Lloyd
 *     2022 René Meusel, Michael Boric - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_SHAKE_CIPHER_H_
#define BOTAN_SHAKE_CIPHER_H_

#include <botan/stream_cipher.h>
#include <botan/secmem.h>

namespace Botan {

/**
* Base class for SHAKE-based XOFs presented as a stream cipher
*/
class SHAKE_Cipher : public StreamCipher
   {
   protected:
      explicit SHAKE_Cipher(size_t shake_rate);

   public:
      /**
      * Produce more XOF output
      */
      void cipher(const uint8_t in[], uint8_t out[], size_t length) override final;

      void write_keystream(uint8_t out[], size_t length) override;

      /**
      * Seeking is not supported, this function will throw
      */
      void seek(uint64_t offset) override final;

      /**
      * IV not supported, this function will throw unless iv_len == 0
      */
      void set_iv(const uint8_t iv[], size_t iv_len) override final;

      void clear() override final;

      Key_Length_Specification key_spec() const override final;

      bool has_keying_material() const override final;

   private:
      void key_schedule(const uint8_t key[], size_t key_len) override final;

   protected:
      size_t m_shake_rate;

      secure_vector<uint64_t> m_state; // internal state
      secure_vector<uint8_t> m_buffer; // ciphertext buffer
      size_t m_buf_pos; // position in m_buffer
   };

class SHAKE_128_Cipher final : public SHAKE_Cipher
   {
   public:
      SHAKE_128_Cipher();

      std::string name() const override
         { return "SHAKE-128"; }

      std::unique_ptr<StreamCipher> new_object() const override
         { return std::make_unique<SHAKE_128_Cipher>(); }
   };

class SHAKE_256_Cipher final : public SHAKE_Cipher
   {
   public:
      SHAKE_256_Cipher();

      std::string name() const override
         { return "SHAKE-256"; }

      std::unique_ptr<StreamCipher> new_object() const override
         { return std::make_unique<SHAKE_256_Cipher>(); }
   };

}

#endif
