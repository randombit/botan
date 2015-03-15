/*
* ECDH implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*     2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pk_utils.h>
#include <botan/ecdh.h>

namespace Botan {

namespace {

/**
* ECDH operation
*/
class ECDH_KA_Operation : public PK_Ops::Key_Agreement_with_KDF
   {
   public:
      typedef ECDH_PrivateKey Key_Type;

      ECDH_KA_Operation(const ECDH_PrivateKey& key, const std::string& kdf) :
         PK_Ops::Key_Agreement_with_KDF(kdf),
         curve(key.domain().get_curve()),
         cofactor(key.domain().get_cofactor())
         {
         l_times_priv = inverse_mod(cofactor, key.domain().get_order()) * key.private_value();
         }

      secure_vector<byte> raw_agree(const byte w[], size_t w_len)
         {
         PointGFp point = OS2ECP(w, w_len, curve);
         PointGFp S = (cofactor * point) * l_times_priv;
         BOTAN_ASSERT(S.on_the_curve(), "ECDH agreed value was on the curve");
         return BigInt::encode_1363(S.get_affine_x(), curve.get_p().bytes());
         }
   private:
      const CurveGFp& curve;
      const BigInt& cofactor;
      BigInt l_times_priv;
   };

}

BOTAN_REGISTER_PK_KEY_AGREE_OP("ECDH", ECDH_KA_Operation);

}
