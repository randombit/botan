/*************************************************
* RSA Header File                                *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_RSA_H__
#define BOTAN_RSA_H__

#include <botan/if_algo.h>

namespace Botan {

/*************************************************
* RSA Public Key                                 *
*************************************************/
class BOTAN_DLL RSA_PublicKey : public PK_Encrypting_Key,
                                public PK_Verifying_with_MR_Key,
                                public virtual IF_Scheme_PublicKey
   {
   public:
      std::string algo_name() const { return "RSA"; }

      SecureVector<byte> encrypt(const byte[], u32bit,
                                 RandomNumberGenerator& rng) const;

      SecureVector<byte> verify(const byte[], u32bit) const;

      RSA_PublicKey() {}
      RSA_PublicKey(const BigInt&, const BigInt&);
   protected:
      BigInt public_op(const BigInt&) const;
   };

/*************************************************
* RSA Private Key                                *
*************************************************/
class BOTAN_DLL RSA_PrivateKey : public RSA_PublicKey,
                                 public PK_Decrypting_Key,
                                 public PK_Signing_Key,
                                 public IF_Scheme_PrivateKey
   {
   public:
      SecureVector<byte> sign(const byte[], u32bit,
                              RandomNumberGenerator&) const;

      SecureVector<byte> decrypt(const byte[], u32bit) const;

      bool check_key(RandomNumberGenerator& rng, bool) const;

      RSA_PrivateKey() {}

      RSA_PrivateKey(RandomNumberGenerator&,
                     const BigInt& p, const BigInt& q, const BigInt& e,
                     const BigInt& d = 0, const BigInt& n = 0);

      RSA_PrivateKey(RandomNumberGenerator&, u32bit bits, u32bit = 65537);
   private:
      BigInt private_op(const byte[], u32bit) const;
   };

}

#endif
