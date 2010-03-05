/*
* GOST 34.10-2001
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_GOST_3410_KEY_H__
#define BOTAN_GOST_3410_KEY_H__

#include <botan/ecc_key.h>
#include <botan/pk_ops.h>

namespace Botan {

/**
* This class represents GOST_3410 Public Keys.
*/
class BOTAN_DLL GOST_3410_PublicKey : public virtual EC_PublicKey,
                                      public PK_Verifying_wo_MR_Key
   {
   public:

      /**
      * Construct a public key from a given public point.
      * @param dom_par the domain parameters associated with this key
      * @param public_point the public point defining this key
      */
      GOST_3410_PublicKey(const EC_Domain_Params& dom_par,
                          const PointGFp& public_point) :
         EC_PublicKey(dom_par, public_point) {}

      /**
      * Construct from X.509 algorithm id and subject public key bits
      */
      GOST_3410_PublicKey(const AlgorithmIdentifier& alg_id,
                          const MemoryRegion<byte>& key_bits);

      /**
      * Get this keys algorithm name.
      * @result this keys algorithm name
      */
      std::string algo_name() const { return "GOST-34.10"; }

      AlgorithmIdentifier algorithm_identifier() const;

      MemoryVector<byte> x509_subject_public_key() const;

      /**
      * Get the maximum number of bits allowed to be fed to this key.
      * This is the bitlength of the order of the base point.

      * @result the maximum number of input bits
      */
      u32bit max_input_bits() const { return domain().get_order().bits(); }

      u32bit message_parts() const { return 2; }

      u32bit message_part_size() const
         { return domain().get_order().bytes(); }

      /**
      * Verify a message with this key.
      * @param message the byte array containing the message
      * @param mess_len the number of bytes in the message byte array
      * @param signature the byte array containing the signature
      * @param sig_len the number of bytes in the signature byte array
      */
      bool verify(const byte message[], u32bit mess_len,
                  const byte signature[], u32bit sig_len) const;

   protected:
      GOST_3410_PublicKey() {}
   };

/**
* This class represents GOST_3410 Private Keys
*/
class BOTAN_DLL GOST_3410_PrivateKey : public GOST_3410_PublicKey,
                                       public EC_PrivateKey,
                                       public PK_Signing_Key
   {
   public:

      GOST_3410_PrivateKey(const AlgorithmIdentifier& alg_id,
                           const MemoryRegion<byte>& key_bits) :
         EC_PrivateKey(alg_id, key_bits) {}

      /**
      * Generate a new private key
      * @param the domain parameters to used for this key
      */
      GOST_3410_PrivateKey(RandomNumberGenerator& rng,
                           const EC_Domain_Params& domain) :
         EC_PrivateKey(rng, domain) {}

      /**
      * Load a private key
      * @param domain parameters
      * @param x the private key
      */
      GOST_3410_PrivateKey(const EC_Domain_Params& domain, const BigInt& x) :
         EC_PrivateKey(domain, x) {}

      AlgorithmIdentifier pkcs8_algorithm_identifier() const
         { return EC_PublicKey::algorithm_identifier(); }
   };

class BOTAN_DLL GOST_3410_Signature_Operation : public PK_Ops::Signature
   {
   public:
      GOST_3410_Signature_Operation(const GOST_3410_PrivateKey& gost_3410);

      u32bit message_parts() const { return 2; }
      u32bit message_part_size() const { return order.bytes(); }
      u32bit max_input_bits() const { return order.bits(); }

      SecureVector<byte> sign(const byte msg[], u32bit msg_len,
                              RandomNumberGenerator& rng);

   private:
      const PointGFp& base_point;
      const BigInt& order;
      const BigInt& x;
   };

class BOTAN_DLL GOST_3410_Verification_Operation : public PK_Ops::Verification
   {
   public:
      GOST_3410_Verification_Operation(const GOST_3410_PublicKey& gost);

      u32bit message_parts() const { return 2; }
      u32bit message_part_size() const { return order.bytes(); }
      u32bit max_input_bits() const { return order.bits(); }

      bool with_recovery() const { return false; }

      bool verify(const byte msg[], u32bit msg_len,
                  const byte sig[], u32bit sig_len);
   private:
      const PointGFp& base_point;
      const PointGFp& public_point;
      const BigInt& order;
   };

}

#endif
