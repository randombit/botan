/*
* Nyberg-Rueppel
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_NYBERG_RUEPPEL_H__
#define BOTAN_NYBERG_RUEPPEL_H__

#include <botan/dl_algo.h>
#include <botan/pk_ops.h>
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

      DL_Group::Format group_format() const { return DL_Group::ANSI_X9_57; }

      u32bit message_parts() const { return 2; }
      u32bit message_part_size() const { return group_q().bytes(); }
      u32bit max_input_bits() const { return (group_q().bits() - 1); }

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
      bool check_key(RandomNumberGenerator& rng, bool strong) const;

      NR_PrivateKey(const AlgorithmIdentifier& alg_id,
                    const MemoryRegion<byte>& key_bits,
                    RandomNumberGenerator& rng);

      NR_PrivateKey(RandomNumberGenerator& rng,
                    const DL_Group& group,
                    const BigInt& x = 0);
   };

class BOTAN_DLL NR_Signature_Operation : public PK_Ops::Signature_Operation
   {
   public:
      NR_Signature_Operation(const NR_PrivateKey& nr);

      u32bit message_parts() const { return 2; }
      u32bit message_part_size() const { return q.bytes(); }
      u32bit max_input_bits() const { return (q.bits() - 1); }

      SecureVector<byte> sign(const byte msg[], u32bit msg_len,
                              RandomNumberGenerator& rng);
   private:
      const BigInt& q;
      const BigInt& x;
      Fixed_Base_Power_Mod powermod_g_p;
      Modular_Reducer mod_q;
   };

class BOTAN_DLL NR_Verification_Operation : public PK_Ops::Verification
   {
   public:
      NR_Verification_Operation(const NR_PublicKey& nr);

      u32bit message_parts() const { return 2; }
      u32bit message_part_size() const { return q.bytes(); }
      u32bit max_input_bits() const { return (q.bits() - 1); }

      bool with_recovery() const { return true; }

      SecureVector<byte> verify_mr(const byte msg[], u32bit msg_len);
   private:
      const BigInt& q;
      const BigInt& y;

      Fixed_Base_Power_Mod powermod_g_p, powermod_y_p;
      Modular_Reducer mod_p, mod_q;
   };

}

#endif
