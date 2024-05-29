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
            PK_Ops::Key_Agreement_with_KDF(kdf), m_group(key.domain()), m_rng(rng) {
         m_l_times_priv = m_group.inverse_mod_order(m_group.get_cofactor()) * key.private_value();
      }

      size_t agreed_value_size() const override { return m_group.get_p_bytes(); }

      secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override {
         EC_Point input_point = m_group.get_cofactor() * m_group.OS2ECP(w, w_len);
         input_point.randomize_repr(m_rng);

         const EC_Point S = m_group.blinded_var_point_multiply(input_point, m_l_times_priv, m_rng, m_ws);

         if(S.on_the_curve() == false) {
            throw Internal_Error("ECDH agreed value was not on the curve");
         }

         return S.x_bytes();
      }

   private:
      const EC_Group m_group;
      BigInt m_l_times_priv;
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
