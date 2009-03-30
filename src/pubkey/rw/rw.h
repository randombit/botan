/*
* Rabin-Williams
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_RW_H__
#define BOTAN_RW_H__

#include <botan/if_algo.h>

namespace Botan {

/*
* Rabin-Williams Public Key
*/
class BOTAN_DLL RW_PublicKey : public PK_Verifying_with_MR_Key,
                               public virtual IF_Scheme_PublicKey
   {
   public:
      std::string algo_name() const { return "RW"; }

      SecureVector<byte> verify(const byte[], u32bit) const;

      RW_PublicKey() {}
      RW_PublicKey(const BigInt&, const BigInt&);
   protected:
      BigInt public_op(const BigInt&) const;
   };

/*
* Rabin-Williams Private Key
*/
class BOTAN_DLL RW_PrivateKey : public RW_PublicKey,
                                public PK_Signing_Key,
                                public IF_Scheme_PrivateKey
   {
   public:
      SecureVector<byte> sign(const byte[], u32bit,
                              RandomNumberGenerator& rng) const;

      bool check_key(RandomNumberGenerator& rng, bool) const;

      RW_PrivateKey() {}

      RW_PrivateKey(RandomNumberGenerator&,
                    const BigInt&, const BigInt&, const BigInt&,
                    const BigInt& = 0, const BigInt& = 0);

      RW_PrivateKey(RandomNumberGenerator& rng, u32bit bits, u32bit = 2);
   };

}

#endif
