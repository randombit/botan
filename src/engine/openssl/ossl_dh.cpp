/*
* OpenSSL Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eng_ossl.h>
#include <botan/bn_wrap.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x0090700F
  #error Your OpenSSL install is too old, upgrade to 0.9.7 or later
#endif

namespace Botan {

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)

namespace {

/*
* OpenSSL DH Operation
*/
class OpenSSL_DH_Op : public DH_Operation
   {
   public:
      BigInt agree(const BigInt& i) const;
      DH_Operation* clone() const { return new OpenSSL_DH_Op(*this); }

      OpenSSL_DH_Op(const DL_Group& group, const BigInt& x_bn) :
         x(x_bn), p(group.get_p()) {}
   private:
      OSSL_BN x, p;
      OSSL_BN_CTX ctx;
   };

/*
* OpenSSL DH Key Agreement Operation
*/
BigInt OpenSSL_DH_Op::agree(const BigInt& i_bn) const
   {
   OSSL_BN i(i_bn), r;
   BN_mod_exp(r.value, i.value, x.value, p.value, ctx.value);
   return r.to_bigint();
   }

}

/*
* Acquire a DH op
*/
DH_Operation* OpenSSL_Engine::dh_op(const DL_Group& group,
                                    const BigInt& x) const
   {
   return new OpenSSL_DH_Op(group, x);
   }
#endif

}
