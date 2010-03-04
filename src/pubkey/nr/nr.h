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

      SecureVector<byte> verify(const byte sig[], u32bit sig_len) const;

      u32bit max_input_bits() const { return (group_q().bits() - 1); }

      DL_Group::Format group_format() const { return DL_Group::ANSI_X9_57; }
      u32bit message_parts() const { return 2; }
      u32bit message_part_size() const { return group_q().bytes(); }

      NR_PublicKey(const AlgorithmIdentifier& alg_id,
                   const MemoryRegion<byte>& key_bits);

      NR_PublicKey(const DL_Group& group, const BigInt& pub_key);
   protected:
      NR_PublicKey() {}
      NR_Core core;
   };

/*
* Nyberg-Rueppel Private Key
*/
class BOTAN_DLL NR_PrivateKey : public NR_PublicKey,
                                public PK_Signing_Key,
                                public virtual DL_Scheme_PrivateKey
   {
   public:
      SecureVector<byte> sign(const byte msg[], u32bit msg_len,
                              RandomNumberGenerator& rng) const;

      bool check_key(RandomNumberGenerator& rng, bool strong) const;

      NR_PrivateKey(const AlgorithmIdentifier& alg_id,
                    const MemoryRegion<byte>& key_bits,
                    RandomNumberGenerator& rng);

      NR_PrivateKey(RandomNumberGenerator& rng,
                    const DL_Group& group,
                    const BigInt& x = 0);
   };

}

#endif
