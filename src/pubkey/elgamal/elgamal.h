/*
* ElGamal
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ELGAMAL_H__
#define BOTAN_ELGAMAL_H__

#include <botan/dl_algo.h>
#include <botan/elg_core.h>

namespace Botan {

/*
* ElGamal Public Key
*/
class BOTAN_DLL ElGamal_PublicKey : public PK_Encrypting_Key,
                                    public virtual DL_Scheme_PublicKey
   {
   public:
      std::string algo_name() const { return "ElGamal"; }
      DL_Group::Format group_format() const { return DL_Group::ANSI_X9_42; }

      SecureVector<byte> encrypt(const byte[], u32bit,
                                 RandomNumberGenerator& rng) const;
      u32bit max_input_bits() const;

      ElGamal_PublicKey() {}
      ElGamal_PublicKey(const DL_Group&, const BigInt&);
   protected:
      ELG_Core core;
   private:
      void X509_load_hook();
   };

/*
* ElGamal Private Key
*/
class BOTAN_DLL ElGamal_PrivateKey : public ElGamal_PublicKey,
                                     public PK_Decrypting_Key,
                                     public virtual DL_Scheme_PrivateKey
   {
   public:
      SecureVector<byte> decrypt(const byte[], u32bit) const;

      bool check_key(RandomNumberGenerator& rng, bool) const;

      ElGamal_PrivateKey() {}
      ElGamal_PrivateKey(RandomNumberGenerator&, const DL_Group&,
                         const BigInt& = 0);
   private:
      void PKCS8_load_hook(RandomNumberGenerator&, bool = false);
   };

}

#endif
