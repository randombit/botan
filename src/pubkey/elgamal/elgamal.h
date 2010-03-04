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

      u32bit max_input_bits() const { return (group_p().bits() - 1); }

      SecureVector<byte> encrypt(const byte msg[], u32bit msg_len,
                                 RandomNumberGenerator& rng) const;

      ElGamal_PublicKey(const AlgorithmIdentifier& alg_id,
                        const MemoryRegion<byte>& key_bits) :
         DL_Scheme_PublicKey(alg_id, key_bits, DL_Group::ANSI_X9_42)
         { core = ELG_Core(group, y); }

      ElGamal_PublicKey(const DL_Group& group, const BigInt& y);
   protected:
      ElGamal_PublicKey() {}
      ELG_Core core;
   };

/*
* ElGamal Private Key
*/
class BOTAN_DLL ElGamal_PrivateKey : public ElGamal_PublicKey,
                                     public PK_Decrypting_Key,
                                     public virtual DL_Scheme_PrivateKey
   {
   public:
      SecureVector<byte> decrypt(const byte msg[], u32bit msg_len) const;

      bool check_key(RandomNumberGenerator& rng, bool) const;

      ElGamal_PrivateKey(const AlgorithmIdentifier& alg_id,
                         const MemoryRegion<byte>& key_bits,
                         RandomNumberGenerator& rng);

      ElGamal_PrivateKey(RandomNumberGenerator& rng,
                         const DL_Group& group,
                         const BigInt& priv_key = 0);
   };

}

#endif
