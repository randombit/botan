/*************************************************
* RSA Header File                                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_RSA_H__
#define BOTAN_RSA_H__

#include <botan/if_algo.h>

namespace Botan {

/*************************************************
* RSA Public Key                                 *
*************************************************/
class RSA_PublicKey : public PK_Encrypting_Key,
                      public PK_Verifying_with_MR_Key,
                      public virtual IF_Scheme_PublicKey
   {
   public:
      std::string algo_name() const { return "RSA"; }

      SecureVector<byte> encrypt(const byte[], u32bit) const;
      SecureVector<byte> verify(const byte[], u32bit) const;

      RSA_PublicKey() {}
      RSA_PublicKey(const BigInt&, const BigInt&);
   protected:
      BigInt public_op(const BigInt&) const;
   };

/*************************************************
* RSA Private Key                                *
*************************************************/
class RSA_PrivateKey : public RSA_PublicKey,
                       public PK_Decrypting_Key,
                       public PK_Signing_Key,
                       public IF_Scheme_PrivateKey
   {
   public:
      SecureVector<byte> decrypt(const byte[], u32bit) const;
      SecureVector<byte> sign(const byte[], u32bit) const;

      bool check_key(bool) const;

      RSA_PrivateKey() {}
      RSA_PrivateKey(const BigInt&, const BigInt&, const BigInt&,
                     const BigInt& = 0, const BigInt& = 0);
      RSA_PrivateKey(u32bit, u32bit = 65537);
   private:
      BigInt private_op(const byte[], u32bit) const;
   };

}

#endif
