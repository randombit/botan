/*
* RC4
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_RC4_H_
#define BOTAN_RC4_H_

#include <botan/stream_cipher.h>
#include <botan/types.h>

namespace Botan {

/**
* RC4 stream cipher
*/
class RC4 final : public StreamCipher {
   public:
      void clear() override;
      std::string name() const override;

      std::unique_ptr<StreamCipher> new_object() const override;

      Key_Length_Specification key_spec() const override;

      void seek(uint64_t offset) override;

      bool has_keying_material() const override;

      size_t buffer_size() const override;

      /**
      * @param skip skip this many initial bytes in the keystream
      */
      explicit RC4(size_t skip = 0);

      ~RC4() override { clear(); }

   private:
      void key_schedule(std::span<const uint8_t> key) override;
      void cipher_bytes(const uint8_t in[], uint8_t out[], size_t length) override;
      void set_iv_bytes(const uint8_t iv[], size_t iv_len) override;
      void generate();

      const size_t m_SKIP;
      uint8_t m_X = 0;
      uint8_t m_Y = 0;
      secure_vector<uint8_t> m_state;
      secure_vector<uint8_t> m_buffer;
      size_t m_position = 0;
};

}  // namespace Botan

#endif
