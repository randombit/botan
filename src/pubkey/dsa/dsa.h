/*
* DSA
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DSA_H__
#define BOTAN_DSA_H__

#include <botan/dl_algo.h>
#include <botan/pk_ops.h>
#include <botan/reducer.h>
#include <botan/pow_mod.h>
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
      u32bit message_part_size() const { return group_q().bytes(); }
      u32bit max_input_bits() const { return group_q().bits(); }

      bool verify(const byte msg[], u32bit msg_len,
                  const byte sig[], u32bit sig_len) const;

      DSA_PublicKey(const AlgorithmIdentifier& alg_id,
                    const MemoryRegion<byte>& key_bits) :
         DL_Scheme_PublicKey(alg_id, key_bits, DL_Group::ANSI_X9_57)
         {
         core = DSA_Core(group, y);
         }

      DSA_PublicKey(const DL_Group& group, const BigInt& y);
   protected:
      DSA_PublicKey() {}
      DSA_Core core;
   };

/*
* DSA Private Key
*/
class BOTAN_DLL DSA_PrivateKey : public DSA_PublicKey,
                                 public PK_Signing_Key,
                                 public virtual DL_Scheme_PrivateKey
   {
   public:
      DSA_PrivateKey(const AlgorithmIdentifier& alg_id,
                     const MemoryRegion<byte>& key_bits,
                     RandomNumberGenerator& rng);

      DSA_PrivateKey(RandomNumberGenerator& rng,
                     const DL_Group& group,
                     const BigInt& private_key = 0);

      bool check_key(RandomNumberGenerator& rng, bool strong) const;
   };

class BOTAN_DLL DSA_Signature_Operation : public PK_Ops::Signature_Operation
   {
   public:
      DSA_Signature_Operation(const DSA_PrivateKey& dsa);

      u32bit message_parts() const { return 2; }
      u32bit message_part_size() const { return q.bytes(); }
      u32bit max_input_bits() const { return q.bits(); }

      SecureVector<byte> sign(const byte msg[], u32bit msg_len,
                              RandomNumberGenerator& rng);
   private:
      const BigInt& q;
      const BigInt& x;
      Fixed_Base_Power_Mod powermod_g_p;
      Modular_Reducer mod_q;
   };

class BOTAN_DLL DSA_Verification_Operation : public PK_Ops::Verification
   {
   public:
      DSA_Verification_Operation(const DSA_PublicKey& dsa);

      u32bit message_parts() const { return 2; }
      u32bit message_part_size() const { return q.bytes(); }
      u32bit max_input_bits() const { return q.bits(); }

      bool with_recovery() const { return false; }

      bool verify(const byte msg[], u32bit msg_len,
                  const byte sig[], u32bit sig_len);
   private:
      const BigInt& q;
      const BigInt& y;

      Fixed_Base_Power_Mod powermod_g_p, powermod_y_p;
      Modular_Reducer mod_p, mod_q;
   };

}

#endif
