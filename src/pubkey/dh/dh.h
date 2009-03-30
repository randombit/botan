/*
* Diffie-Hellman
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DIFFIE_HELLMAN_H__
#define BOTAN_DIFFIE_HELLMAN_H__

#include <botan/dl_algo.h>
#include <botan/dh_core.h>

namespace Botan {

/**
* This class represents Diffie-Hellman public keys.
*/
class BOTAN_DLL DH_PublicKey : public virtual DL_Scheme_PublicKey
   {
   public:
      std::string algo_name() const { return "DH"; }

      MemoryVector<byte> public_value() const;
      u32bit max_input_bits() const;

      DL_Group::Format group_format() const { return DL_Group::ANSI_X9_42; }

      /**
      * Construct an uninitialized key. Use this constructor if you wish
      * to decode an encoded key into the new instance.
      */
      DH_PublicKey() {}

      /**
      * Construct a public key with the specified parameters.
      * @param grp the DL group to use in the key
      * @param y the public value y
      */
      DH_PublicKey(const DL_Group& grp, const BigInt& y);
   private:
      void X509_load_hook();
   };

/**
* This class represents Diffie-Hellman private keys.
*/
class BOTAN_DLL DH_PrivateKey : public DH_PublicKey,
                                public PK_Key_Agreement_Key,
                                public virtual DL_Scheme_PrivateKey
   {
   public:
      SecureVector<byte> derive_key(const byte other[], u32bit length) const;
      SecureVector<byte> derive_key(const DH_PublicKey& other) const;
      SecureVector<byte> derive_key(const BigInt& other) const;

      MemoryVector<byte> public_value() const;

      /**
      * Construct an uninitialized key. Use this constructor if you wish
      * to decode an encoded key into the new instance.
      */
      DH_PrivateKey() {}

      /**
      * Construct a private key with predetermined value.
      * @param rng random number generator to use
      * @param grp the group to be used in the key
      * @param x the key's secret value (or if zero, generate a new key)
      */
      DH_PrivateKey(RandomNumberGenerator& rng, const DL_Group& grp,
                    const BigInt& x = 0);
   private:
      void PKCS8_load_hook(RandomNumberGenerator& rng, bool = false);
      DH_Core core;
   };

}

#endif
