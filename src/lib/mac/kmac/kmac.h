/*
* KMAC
* (C) 2023 Jack Lloyd
* (C) 2023 Falko Strenzke
* (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_KMAC_H_
#define BOTAN_KMAC_H_

#include <botan/mac.h>

#include <botan/internal/cshake_xof.h>

namespace Botan {

/**
* KMAC-256 as specified in NIST SP.800-185 Section 4
*/
class KMAC256 final : public MessageAuthenticationCode {
   public:
      void clear() override;
      std::string name() const override;
      std::unique_ptr<MessageAuthenticationCode> new_object() const override;

      size_t output_length() const override;

      Key_Length_Specification key_spec() const override;

      void start_msg(const uint8_t nonce[], size_t nonce_len) final;
      explicit KMAC256(size_t output_byte_length);

      KMAC256(const KMAC256&) = delete;
      KMAC256& operator=(const KMAC256&) = delete;

      bool has_keying_material() const override;

   private:
      void add_data(std::span<const uint8_t>) final;
      void final_result(std::span<uint8_t>) final;
      void key_schedule(std::span<const uint8_t>) final;

      size_t m_output_bit_length;
      secure_vector<uint8_t> m_key;
      bool m_message_started;

      cSHAKE_256_XOF m_cshake;
};

}  // namespace Botan

#endif
