/*
* HMAC
* (C) 1999-2007,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HMAC_H_
#define BOTAN_HMAC_H_

#include <botan/hash.h>
#include <botan/mac.h>

namespace Botan {

/**
* HMAC
*/
class HMAC final : public MessageAuthenticationCode {
   public:
      void clear() override;
      std::string name() const override;
      std::unique_ptr<MessageAuthenticationCode> new_object() const override;

      size_t output_length() const override;

      Key_Length_Specification key_spec() const override;

      bool has_keying_material() const override;

      /**
      * @param hash the hash to use for HMACing
      */
      explicit HMAC(std::unique_ptr<HashFunction> hash);

      HMAC(const HMAC&) = delete;
      HMAC& operator=(const HMAC&) = delete;

   private:
      void add_data(std::span<const uint8_t>) override;
      void final_result(std::span<uint8_t>) override;
      void key_schedule(std::span<const uint8_t>) override;

      std::unique_ptr<HashFunction> m_hash;
      secure_vector<uint8_t> m_ikey, m_okey;
      size_t m_hash_output_length;
      size_t m_hash_block_size;
};

}  // namespace Botan

#endif
