/*
* ECDH implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*     2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ecdh.h>

#include <botan/numthry.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

std::unique_ptr<Public_Key> ECDH_PrivateKey::public_key() const {
   return std::make_unique<ECDH_PublicKey>(domain(), public_point());
}

namespace {

/**
* ECDH operation
*/
class ECDH_KA_Operation final : public PK_Ops::Key_Agreement_with_KDF {
   public:
      ECDH_KA_Operation(const ECDH_PrivateKey& key, std::string_view kdf, RandomNumberGenerator& rng) :
            PK_Ops::Key_Agreement_with_KDF(kdf),
            m_group(key.domain()),
            m_l_times_priv(mul_cofactor_inv(m_group, key._private_key())),
            m_rng(rng) {}

      size_t agreed_value_size() const override { return m_group.get_p_bytes(); }

      secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override {
         if(m_group.has_cofactor()) {
            EC_AffinePoint input_point(m_group, m_group.get_cofactor() * m_group.OS2ECP(w, w_len));
            return input_point.mul(m_l_times_priv, m_rng, m_ws).x_bytes();
         } else {
            if(auto input_point = EC_AffinePoint::deserialize(m_group, {w, w_len})) {
               return input_point->mul(m_l_times_priv, m_rng, m_ws).x_bytes();
            } else {
               throw Decoding_Error("ECDH - Invalid elliptic curve point");
            }
         }
      }

   private:
      static EC_Scalar mul_cofactor_inv(const EC_Group& group, const EC_Scalar& x) {
         // We implement BSI TR-03111 ECKAEG which only matters in the (rare/deprecated)
         // case of a curve with cofactor.

         if(group.has_cofactor()) {
            // We could precompute this but cofactors are rare
            auto l = group.inverse_mod_order(group.get_cofactor());
            return x * EC_Scalar::from_bigint(group, l);
         } else {
            return x;
         }
      }

      const EC_Group m_group;
      const EC_Scalar m_l_times_priv;
      RandomNumberGenerator& m_rng;
      std::vector<BigInt> m_ws;
};

}  // namespace

std::unique_ptr<Private_Key> ECDH_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<ECDH_PrivateKey>(rng, domain());
}

std::unique_ptr<PK_Ops::Key_Agreement> ECDH_PrivateKey::create_key_agreement_op(RandomNumberGenerator& rng,
                                                                                std::string_view params,
                                                                                std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<ECDH_KA_Operation>(*this, params, rng);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
