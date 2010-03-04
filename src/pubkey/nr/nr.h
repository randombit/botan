/*
* Nyberg-Rueppel
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_NYBERG_RUEPPEL_H__
#define BOTAN_NYBERG_RUEPPEL_H__

#include <botan/dl_algo.h>
#include <botan/nr_core.h>

namespace Botan {

/*
* Nyberg-Rueppel Public Key
*/
class BOTAN_DLL NR_PublicKey : public PK_Verifying_with_MR_Key,
                               public virtual DL_Scheme_PublicKey
   {
   public:
      std::string algo_name() const { return "NR"; }

      SecureVector<byte> verify(const byte[], u32bit) const;
      u32bit max_input_bits() const;

      DL_Group::Format group_format() const { return DL_Group::ANSI_X9_57; }
      u32bit message_parts() const { return 2; }
      u32bit message_part_size() const;

      NR_PublicKey(const AlgorithmIdentifier& alg_id,
                   const MemoryRegion<byte>& key_bits) :
         DL_Scheme_PublicKey(alg_id, key_bits, DL_Group::ANSI_X9_57)
         { X509_load_hook(); }

      NR_PublicKey(const DL_Group&, const BigInt&);
   protected:
      NR_PublicKey() {}
      NR_Core core;
   private:
      void X509_load_hook();
   };

/*
* Nyberg-Rueppel Private Key
*/
class BOTAN_DLL NR_PrivateKey : public NR_PublicKey,
                                public PK_Signing_Key,
                                public virtual DL_Scheme_PrivateKey
   {
   public:
      SecureVector<byte> sign(const byte[], u32bit,
                              RandomNumberGenerator& rng) const;

      bool check_key(RandomNumberGenerator& rng, bool) const;

      NR_PrivateKey(const AlgorithmIdentifier& alg_id,
                    const MemoryRegion<byte>& key_bits,
                    RandomNumberGenerator& rng) :
         DL_Scheme_PrivateKey(alg_id, key_bits, DL_Group::ANSI_X9_57)
         {
         PKCS8_load_hook(rng);
         }

      NR_PrivateKey(RandomNumberGenerator&, const DL_Group&,
                    const BigInt& = 0);
   private:
      void PKCS8_load_hook(RandomNumberGenerator&, bool = false);
   };

}

#endif
