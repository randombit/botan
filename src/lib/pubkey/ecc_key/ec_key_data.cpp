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

EC_PrivateKey_Data::EC_PrivateKey_Data(EC_Group group, EC_Scalar x) :
      m_group(std::move(group)), m_scalar(std::move(x)), m_legacy_x(m_scalar.to_bigint()) {}

namespace {

EC_Scalar decode_ec_secret_key_scalar(const EC_Group& group, std::span<const uint8_t> bytes) {
   const size_t order_bytes = group.get_order_bytes();

   if(bytes.size() < order_bytes) {
      /*
      * Older versions had a bug which caused secret keys to not be encoded to
      * the full byte length of the order if there were leading zero bytes. This
      * was particularly a problem for P-521, where on average half of keys do
      * not have their high bit set and so can be encoded in 65 bytes, vs 66
      * bytes for the full order.
      *
      * To accomodate this, zero prefix the key if we see such a short input
      */
      secure_vector<uint8_t> padded_sk(order_bytes);
      copy_mem(std::span{padded_sk}.last(bytes.size()), bytes);
      return decode_ec_secret_key_scalar(group, padded_sk);
   }

   if(auto s = EC_Scalar::deserialize(group, bytes)) {
      return s.value();
   } else {
      throw Decoding_Error("EC private key is invalid for this group");
   }
}

}  // namespace

EC_PrivateKey_Data::EC_PrivateKey_Data(EC_Group group, std::span<const uint8_t> bytes) :
      m_group(std::move(group)),
      m_scalar(decode_ec_secret_key_scalar(m_group, bytes)),
      m_legacy_x(m_scalar.to_bigint()) {}

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
