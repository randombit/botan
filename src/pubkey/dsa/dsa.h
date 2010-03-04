/*
* DSA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DSA_H__
#define BOTAN_DSA_H__

#include <botan/dl_algo.h>
#include <botan/dsa_core.h>

namespace Botan {

/*
* DSA Public Key
*/
class BOTAN_DLL DSA_PublicKey : public PK_Verifying_wo_MR_Key,
                                public virtual DL_Scheme_PublicKey
   {
   public:
      std::string algo_name() const { return "DSA"; }

      DL_Group::Format group_format() const { return DL_Group::ANSI_X9_57; }
      u32bit message_parts() const { return 2; }
      u32bit message_part_size() const;

      bool verify(const byte[], u32bit, const byte[], u32bit) const;
      u32bit max_input_bits() const;

      DSA_PublicKey(const AlgorithmIdentifier& alg_id,
                    const MemoryRegion<byte>& key_bits) :
         DL_Scheme_PublicKey(alg_id, key_bits, DL_Group::ANSI_X9_57)
         { X509_load_hook(); }

      DSA_PublicKey(const DL_Group& group, const BigInt& y);
   protected:
      DSA_PublicKey() {}
      DSA_Core core;
   private:
      void X509_load_hook();
   };

/*
* DSA Private Key
*/
class BOTAN_DLL DSA_PrivateKey : public DSA_PublicKey,
                                 public PK_Signing_Key,
                                 public virtual DL_Scheme_PrivateKey
   {
   public:
      SecureVector<byte> sign(const byte hash[], u32bit hash_len,
                              RandomNumberGenerator& rng) const;

      bool check_key(RandomNumberGenerator& rng, bool strong) const;

      DSA_PrivateKey(const AlgorithmIdentifier& alg_id,
                     const MemoryRegion<byte>& key_bits,
                     RandomNumberGenerator& rng) :
         DL_Scheme_PrivateKey(alg_id, key_bits, DL_Group::ANSI_X9_57)
         {
         PKCS8_load_hook(rng);
         }

      DSA_PrivateKey(RandomNumberGenerator& rng,
                     const DL_Group& group,
                     const BigInt& private_key = 0);

   private:
      void PKCS8_load_hook(RandomNumberGenerator& rng, bool = false);
   };

}

#endif
