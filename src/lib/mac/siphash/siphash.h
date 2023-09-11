/*
* SipHash
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIPHASH_H_
#define BOTAN_SIPHASH_H_

#include <botan/mac.h>

namespace Botan {

class SipHash final : public MessageAuthenticationCode {
   public:
      SipHash(size_t c = 2, size_t d = 4) : m_C(c), m_D(d) {}

      void clear() override;
      std::string name() const override;

      std::unique_ptr<MessageAuthenticationCode> new_object() const override;

      size_t output_length() const override { return 8; }

      bool has_keying_material() const override;

      Key_Length_Specification key_spec() const override { return Key_Length_Specification(16); }

   private:
      void add_data(std::span<const uint8_t>) override;
      void final_result(std::span<uint8_t>) override;
      void key_schedule(std::span<const uint8_t>) override;

      const size_t m_C, m_D;
      secure_vector<uint64_t> m_K;
      secure_vector<uint64_t> m_V;
      uint64_t m_mbuf = 0;
      size_t m_mbuf_pos = 0;
      uint8_t m_words = 0;
};

}  // namespace Botan

#endif
