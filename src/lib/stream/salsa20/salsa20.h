/*
* Salsa20 / XSalsa20
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SALSA20_H_
#define BOTAN_SALSA20_H_

#include <botan/stream_cipher.h>

namespace Botan {

/**
* DJB's Salsa20 (and XSalsa20)
*/
class Salsa20 final : public StreamCipher {
   public:
      bool valid_iv_length(size_t iv_len) const override;
      size_t default_iv_length() const override;
      Key_Length_Specification key_spec() const override;
      void clear() override;
      std::string name() const override;
      std::unique_ptr<StreamCipher> new_object() const override;
      bool has_keying_material() const override;
      void seek(uint64_t offset) override;

      size_t buffer_size() const override;

      // For internal use only
      static void salsa_core(uint8_t output[64], const uint32_t input[16], size_t rounds);

      // For internal use only
      static void hsalsa20(uint32_t output[8], const uint32_t input[16]);

   protected:
      void cipher_bytes(const uint8_t in[], uint8_t out[], size_t length) override;
      void set_iv_bytes(const uint8_t iv[], size_t iv_len) override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      void initialize_state();

      secure_vector<uint32_t> m_key;
      secure_vector<uint32_t> m_state;
      secure_vector<uint8_t> m_buffer;
      size_t m_position = 0;
};

}  // namespace Botan

#endif
