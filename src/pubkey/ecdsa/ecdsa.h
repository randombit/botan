/*
* ECDSA
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ECDSA_KEY_H__
#define BOTAN_ECDSA_KEY_H__

#include <botan/ecc_key.h>
#include <botan/pk_ops.h>

namespace Botan {

/**
* This class represents ECDSA Public Keys.
*/
class BOTAN_DLL ECDSA_PublicKey : public virtual EC_PublicKey
   {
   public:

      /**
      * Construct a public key from a given public point.
      * @param dom_par the domain parameters associated with this key
      * @param public_point the public point defining this key
      */
      ECDSA_PublicKey(const EC_Domain_Params& dom_par,
                      const PointGFp& public_point) :
         EC_PublicKey(dom_par, public_point) {}

      ECDSA_PublicKey(const AlgorithmIdentifier& alg_id,
                      const MemoryRegion<byte>& key_bits) :
         EC_PublicKey(alg_id, key_bits) {}

      /**
      * Get this keys algorithm name.
      * @result this keys algorithm name ("ECDSA")
      */
      std::string algo_name() const { return "ECDSA"; }

      /**
      * Get the maximum number of bits allowed to be fed to this key.
      * This is the bitlength of the order of the base point.
      * @result the maximum number of input bits
      */
      u32bit max_input_bits() const { return domain().get_order().bits(); }

      u32bit message_parts() const { return 2; }

      u32bit message_part_size() const
         { return domain().get_order().bytes(); }

   protected:
      ECDSA_PublicKey() {}
   };

/**
* This class represents ECDSA Private Keys
*/
class BOTAN_DLL ECDSA_PrivateKey : public ECDSA_PublicKey,
                                   public EC_PrivateKey
   {
   public:

      ECDSA_PrivateKey(const AlgorithmIdentifier& alg_id,
                       const MemoryRegion<byte>& key_bits) :
         EC_PrivateKey(alg_id, key_bits) {}

      /**
      * Generate a new private key
      * @param the domain parameters to used for this key
      */
      ECDSA_PrivateKey(RandomNumberGenerator& rng,
                       const EC_Domain_Params& domain) :
         EC_PrivateKey(rng, domain) {}

      /**
      * Load a private key
      * @param domain parameters
      * @param x the private key
      */
      ECDSA_PrivateKey(const EC_Domain_Params& domain, const BigInt& x) :
         EC_PrivateKey(domain, x) {}
   };

class BOTAN_DLL ECDSA_Signature_Operation : public PK_Ops::Signature
   {
   public:
      ECDSA_Signature_Operation(const ECDSA_PrivateKey& ecdsa);

      SecureVector<byte> sign(const byte msg[], u32bit msg_len,
                              RandomNumberGenerator& rng) const;

      u32bit message_parts() const { return 2; }
      u32bit message_part_size() const { return order.bytes(); }
      u32bit max_input_bits() const { return order.bits(); }

   private:
      const PointGFp& base_point;
      const BigInt& order;
      const BigInt& x;
   };

class BOTAN_DLL ECDSA_Verification_Operation : public PK_Ops::Verification
   {
   public:
      ECDSA_Verification_Operation(const ECDSA_PublicKey& ecdsa);

      u32bit message_parts() const { return 2; }
      u32bit message_part_size() const { return order.bytes(); }
      u32bit max_input_bits() const { return order.bits(); }

      bool with_recovery() const { return false; }

      bool verify(const byte msg[], u32bit msg_len,
                  const byte sig[], u32bit sig_len) const;
   private:
      const PointGFp& base_point;
      const PointGFp& public_point;
      const BigInt& order;
   };

}

#endif
