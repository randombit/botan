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

#if defined(BOTAN_HAS_OPENSSL)
  #include <botan/internal/openssl.h>
#endif

namespace Botan {

namespace {

/**
* ECDH operation
*/
class ECDH_KA_Operation final : public PK_Ops::Key_Agreement_with_KDF
   {
   public:

      ECDH_KA_Operation(const ECDH_PrivateKey& key, const std::string& kdf, RandomNumberGenerator& rng) :
         PK_Ops::Key_Agreement_with_KDF(kdf),
         m_curve(key.domain().get_curve()),
         m_cofactor(key.domain().get_cofactor()),
         m_order(key.domain().get_order()),
         m_rng(rng)
         {
         m_l_times_priv = inverse_mod(m_cofactor, m_order) * key.private_value();
         }

      secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override
         {
         PointGFp point = OS2ECP(w, w_len, m_curve);
         PointGFp S = m_cofactor * point;
         Blinded_Point_Multiply blinder(S, m_order);
         S = blinder.blinded_multiply(m_l_times_priv, m_rng);
         BOTAN_ASSERT(S.on_the_curve(), "ECDH agreed value was on the curve");
         return BigInt::encode_1363(S.get_affine_x(), m_curve.get_p().bytes());
         }
   private:
      const CurveGFp& m_curve;
      const BigInt& m_cofactor;
      const BigInt& m_order;
      BigInt m_l_times_priv;
      RandomNumberGenerator& m_rng;

   };

}

std::unique_ptr<PK_Ops::Key_Agreement>
ECDH_PrivateKey::create_key_agreement_op(RandomNumberGenerator& rng,
                                         const std::string& params,
                                         const std::string& provider) const
   {
#if defined(BOTAN_HAS_OPENSSL)
   if(provider == "openssl" || provider.empty())
      {
      try
         {
         return make_openssl_ecdh_ka_op(*this, params);
         }
      catch(Lookup_Error&)
         {
         if(provider == "openssl")
            throw;
         }
      }
#endif

   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Key_Agreement>(new ECDH_KA_Operation(*this, params, rng));

   throw Provider_Not_Found(algo_name(), provider);
   }


}
