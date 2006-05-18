/*************************************************
* ElGamal Header File                            *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_ELGAMAL_H__
#define BOTAN_ELGAMAL_H__

#include <botan/dl_algo.h>
#include <botan/pk_core.h>
#include <botan/blinding.h>

namespace Botan {

/*************************************************
* ElGamal Public Key                             *
*************************************************/
class ElGamal_PublicKey : public PK_Encrypting_Key,
                          public virtual DL_Scheme_PublicKey
   {
   public:
      SecureVector<byte> encrypt(const byte[], u32bit) const;
      u32bit max_input_bits() const;

      ElGamal_PublicKey(const DL_Group&, const BigInt&);
   protected:
      std::string algo_name() const { return "ElGamal"; }
      ElGamal_PublicKey() {}

      ELG_Core core;
   private:
      friend X509_PublicKey* get_public_key(const std::string&);
      DL_Group::Format group_format() const { return DL_Group::ANSI_X9_42; }
      void X509_load_hook();
   };

/*************************************************
* ElGamal Private Key                            *
*************************************************/
class ElGamal_PrivateKey : public ElGamal_PublicKey,
                           public PK_Decrypting_Key,
                           public virtual DL_Scheme_PrivateKey
   {
   public:
      SecureVector<byte> decrypt(const byte[], u32bit) const;

      bool check_key(bool) const;

      ElGamal_PrivateKey(const DL_Group&);
      ElGamal_PrivateKey(const DL_Group&, const BigInt&, const BigInt& = 0);
   private:
      friend PKCS8_PrivateKey* get_private_key(const std::string&);
      void PKCS8_load_hook();
      ElGamal_PrivateKey() {}
   };

}

#endif
