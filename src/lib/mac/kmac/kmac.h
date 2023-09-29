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

namespace Botan {

class cSHAKE_XOF;

class KMAC : public MessageAuthenticationCode {
   protected:
      KMAC(std::unique_ptr<cSHAKE_XOF> cshake, size_t output_bit_length);

   public:
      virtual ~KMAC();

      KMAC(const KMAC&) = delete;
      KMAC& operator=(const KMAC&) = delete;

      void clear() final;
      size_t output_length() const final;
      Key_Length_Specification key_spec() const final;
      bool has_keying_material() const final;

      std::string provider() const final;

   private:
      void start_msg(std::span<const uint8_t> nonce) final;
      void add_data(std::span<const uint8_t>) final;
      void final_result(std::span<uint8_t>) final;
      void key_schedule(std::span<const uint8_t>) final;

   private:
      size_t m_output_bit_length;
      secure_vector<uint8_t> m_encoded_key;
      bool m_message_started;

      std::unique_ptr<cSHAKE_XOF> m_cshake;
};

/**
* KMAC-128 as specified in NIST SP.800-185 Section 4
*/
class KMAC128 final : public KMAC {
   public:
      KMAC128(size_t output_bit_length);
      std::string name() const override;
      std::unique_ptr<MessageAuthenticationCode> new_object() const override;
};

/**
* KMAC-256 as specified in NIST SP.800-185 Section 4
*/
class KMAC256 final : public KMAC {
   public:
      KMAC256(size_t output_bit_length);
      std::string name() const override;
      std::unique_ptr<MessageAuthenticationCode> new_object() const override;
};

}  // namespace Botan

#endif
