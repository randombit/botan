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
#include <botan/internal/keccak_perm.h>

namespace Botan {

/**
* Base class for SHAKE-based XOFs presented as a stream cipher
*/
class SHAKE_Cipher : public StreamCipher {
   protected:
      explicit SHAKE_Cipher(size_t keccak_capacity);

   public:
      /**
      * Seeking is not supported, this function will throw
      */
      void seek(uint64_t offset) final;

      void clear() final;

      Key_Length_Specification key_spec() const final;

      bool has_keying_material() const final { return m_has_keying_material; }

      size_t buffer_size() const final { return m_keccak.byte_rate(); }

   private:
      void key_schedule(std::span<const uint8_t> key) final;
      /**
      * Produce more XOF output
      */
      void cipher_bytes(const uint8_t in[], uint8_t out[], size_t length) final;
      void generate_keystream(uint8_t out[], size_t length) override;

      void generate_keystream_internal(std::span<uint8_t> out);

      /**
      * IV not supported, this function will throw unless iv_len == 0
      */
      void set_iv_bytes(const uint8_t iv[], size_t iv_len) final;

   private:
      Keccak_Permutation m_keccak;
      bool m_has_keying_material;
      secure_vector<uint8_t> m_keystream_buffer;
      size_t m_bytes_generated;
};

class SHAKE_128_Cipher final : public SHAKE_Cipher {
   public:
      SHAKE_128_Cipher();

      std::string name() const override { return "SHAKE-128"; }

      std::unique_ptr<StreamCipher> new_object() const override { return std::make_unique<SHAKE_128_Cipher>(); }
};

class SHAKE_256_Cipher final : public SHAKE_Cipher {
   public:
      SHAKE_256_Cipher();

      std::string name() const override { return "SHAKE-256"; }

      std::unique_ptr<StreamCipher> new_object() const override { return std::make_unique<SHAKE_256_Cipher>(); }
};

}  // namespace Botan

#endif
