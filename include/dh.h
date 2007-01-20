/*************************************************
* Diffie-Hellman Header File                     *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_DIFFIE_HELLMAN_H__
#define BOTAN_DIFFIE_HELLMAN_H__

#include <botan/dl_algo.h>
#include <botan/pk_core.h>

namespace Botan {

/*************************************************
* Diffie-Hellman Public Key                      *
*************************************************/
class DH_PublicKey : public virtual DL_Scheme_PublicKey
   {
   public:
      std::string algo_name() const { return "DH"; }

      MemoryVector<byte> public_value() const;
      u32bit max_input_bits() const;

      DL_Group::Format group_format() const { return DL_Group::ANSI_X9_42; }

      DH_PublicKey() {}
      DH_PublicKey(const DL_Group&, const BigInt&);
   private:
      void X509_load_hook();
   };

/*************************************************
* Diffie-Hellman Private Key                     *
*************************************************/
class DH_PrivateKey : public DH_PublicKey,
                      public PK_Key_Agreement_Key,
                      public virtual DL_Scheme_PrivateKey
   {
   public:
      SecureVector<byte> derive_key(const byte[], u32bit) const;
      SecureVector<byte> derive_key(const DH_PublicKey&) const;
      SecureVector<byte> derive_key(const BigInt&) const;

      MemoryVector<byte> public_value() const;

      DH_PrivateKey() {}
      DH_PrivateKey(const DL_Group&);
      DH_PrivateKey(const DL_Group&, const BigInt&, const BigInt& = 0);
   private:
      void PKCS8_load_hook(bool = false);
      DH_Core core;
   };

}

#endif
