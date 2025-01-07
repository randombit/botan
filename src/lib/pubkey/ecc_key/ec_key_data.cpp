/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ec_key_data.h>

#include <botan/rng.h>

namespace Botan {

EC_PublicKey_Data::EC_PublicKey_Data(EC_Group group, std::span<const uint8_t> bytes) :
      m_group(std::move(group)), m_point(m_group, bytes) {
#if defined(BOTAN_HAS_LEGACY_EC_POINT)
   m_legacy_point = m_point.to_legacy_point();
#endif
}

EC_PrivateKey_Data::EC_PrivateKey_Data(EC_Group group, const BigInt& x) :
      m_group(std::move(group)), m_scalar(EC_Scalar::from_bigint(m_group, x)), m_legacy_x(m_scalar.to_bigint()) {}

EC_PrivateKey_Data::EC_PrivateKey_Data(EC_Group group, EC_Scalar x) :
      m_group(std::move(group)), m_scalar(std::move(x)), m_legacy_x(m_scalar.to_bigint()) {}

EC_PrivateKey_Data::EC_PrivateKey_Data(EC_Group group, std::span<const uint8_t> bytes) :
      m_group(std::move(group)), m_scalar(m_group, bytes), m_legacy_x(m_scalar.to_bigint()) {}

std::shared_ptr<EC_PublicKey_Data> EC_PrivateKey_Data::public_key(RandomNumberGenerator& rng,
                                                                  bool with_modular_inverse) const {
   auto public_point = [&] {
      std::vector<BigInt> ws;
      if(with_modular_inverse) {
         return EC_AffinePoint::g_mul(m_scalar.invert(), rng, ws);
      } else {
         return EC_AffinePoint::g_mul(m_scalar, rng, ws);
      }
   };

   return std::make_shared<EC_PublicKey_Data>(m_group, public_point());
}

std::shared_ptr<EC_PublicKey_Data> EC_PrivateKey_Data::public_key(bool with_modular_inverse) const {
   Null_RNG null_rng;
   return this->public_key(null_rng, with_modular_inverse);
}

void EC_PrivateKey_Data::serialize_to(std::span<uint8_t> output) const {
   m_scalar.serialize_to(output);
}

}  // namespace Botan
