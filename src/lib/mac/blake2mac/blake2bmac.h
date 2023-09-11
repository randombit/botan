/*
* BLAKE2b MAC
* (C) 1999-2007,2014 Jack Lloyd
* (C) 2020           Tom Crowley
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BLAKE2MAC_H_
#define BOTAN_BLAKE2MAC_H_

#include <botan/mac.h>
#include <botan/internal/blake2b.h>

namespace Botan {

/**
* BLAKE2b MAC
*/
class BLAKE2bMAC final : public MessageAuthenticationCode {
   public:
      explicit BLAKE2bMAC(size_t output_bits = 512);

      BLAKE2bMAC(const BLAKE2bMAC&) = delete;
      BLAKE2bMAC& operator=(const BLAKE2bMAC&) = delete;

      std::string name() const override { return m_blake.name(); }

      size_t output_length() const override { return m_blake.output_length(); }

      std::unique_ptr<MessageAuthenticationCode> new_object() const override;

      void clear() override;

      bool has_keying_material() const override { return m_blake.has_keying_material(); }

      Key_Length_Specification key_spec() const override { return m_blake.key_spec(); }

   private:
      void key_schedule(std::span<const uint8_t> key) override { m_blake.set_key(key); }

      void add_data(std::span<const uint8_t> input) override {
         assert_key_material_set();
         m_blake.update(input);
      }

      void final_result(std::span<uint8_t> out) override {
         assert_key_material_set();
         m_blake.final(out);
      }

      BLAKE2b m_blake;
};

}  // namespace Botan

#endif
