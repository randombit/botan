/*************************************************
* Nyberg-Rueppel Header File                     *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_NYBERG_RUEPPEL_H__
#define BOTAN_NYBERG_RUEPPEL_H__

#include <botan/dl_algo.h>
#include <botan/pk_core.h>

namespace Botan {

/*************************************************
* Nyberg-Rueppel Public Key                      *
*************************************************/
class NR_PublicKey : public PK_Verifying_with_MR_Key,
                     public virtual DL_Scheme_PublicKey
   {
   public:
      std::string algo_name() const { return "NR"; }

      SecureVector<byte> verify(const byte[], u32bit) const;
      u32bit max_input_bits() const;

      DL_Group::Format group_format() const { return DL_Group::ANSI_X9_57; }
      u32bit message_parts() const { return 2; }
      u32bit message_part_size() const;

      NR_PublicKey() {}
      NR_PublicKey(const DL_Group&, const BigInt&);
   protected:
      NR_Core core;
   private:
      void X509_load_hook();
   };

/*************************************************
* Nyberg-Rueppel Private Key                     *
*************************************************/
class NR_PrivateKey : public NR_PublicKey,
                      public PK_Signing_Key,
                      public virtual DL_Scheme_PrivateKey
   {
   public:
      SecureVector<byte> sign(const byte[], u32bit) const;

      bool check_key(bool) const;

      NR_PrivateKey() {}
      NR_PrivateKey(const DL_Group&);
      NR_PrivateKey(const DL_Group&, const BigInt&, const BigInt& = 0);
   private:
      void PKCS8_load_hook(bool = false);
   };

}

#endif
