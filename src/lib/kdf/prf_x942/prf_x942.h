/*
* X9.42 PRF
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ANSI_X942_PRF_H_
#define BOTAN_ANSI_X942_PRF_H_

#include <botan/asn1_obj.h>
#include <botan/kdf.h>

namespace Botan {

/**
* PRF from ANSI X9.42
*/
class X942_PRF final : public KDF {
   public:
      std::string name() const override;

      std::unique_ptr<KDF> new_object() const override { return std::make_unique<X942_PRF>(m_key_wrap_oid); }

      explicit X942_PRF(std::string_view oid) : m_key_wrap_oid(OID::from_string(oid)) {}

      explicit X942_PRF(const OID& oid) : m_key_wrap_oid(oid) {}

   private:
      void perform_kdf(std::span<uint8_t> key,
                       std::span<const uint8_t> secret,
                       std::span<const uint8_t> salt,
                       std::span<const uint8_t> label) const override;

   private:
      OID m_key_wrap_oid;
};

}  // namespace Botan

#endif
