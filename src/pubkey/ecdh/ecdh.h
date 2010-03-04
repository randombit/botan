/*
* ECDH
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ECDH_KEY_H__
#define BOTAN_ECDH_KEY_H__

#include <botan/ecc_key.h>

namespace Botan {

/**
* This class represents ECDH Public Keys.
*/
class BOTAN_DLL ECDH_PublicKey : public virtual EC_PublicKey
   {
   public:


      ECDH_PublicKey(const AlgorithmIdentifier& alg_id,
                     const MemoryRegion<byte>& key_bits) :
         EC_PublicKey(alg_id, key_bits) {}

      /**
      * Construct a public key from a given public point.
      * @param dom_par the domain parameters associated with this key
      * @param public_point the public point defining this key
      */
      ECDH_PublicKey(const EC_Domain_Params& dom_par,
                     const PointGFp& public_point) :
         EC_PublicKey(dom_par, public_point) {}

      /**
      * Get this keys algorithm name.
      * @result this keys algorithm name
      */
      std::string algo_name() const { return "ECDH"; }

      /**
      * Get the maximum number of bits allowed to be fed to this key.
      * This is the bitlength of the order of the base point.

      * @result the maximum number of input bits
      */
      u32bit max_input_bits() const { return domain().get_order().bits(); }
   protected:
      ECDH_PublicKey() {}
   };

/**
* This class represents ECDH Private Keys.
*/
class BOTAN_DLL ECDH_PrivateKey : public ECDH_PublicKey,
                                  public EC_PrivateKey,
                                  public PK_Key_Agreement_Key
   {
   public:

      /**
      * Default constructor. Use this one if you want to later fill
      * this object with data from an encoded key.
      */
      ECDH_PrivateKey() {}

      /**
      * Generate a new private key
      * @param the domain parameters to used for this key
      */
      ECDH_PrivateKey(RandomNumberGenerator& rng,
                      const EC_Domain_Params& domain) :
         EC_PrivateKey(rng, domain) {}

      MemoryVector<byte> public_value() const
         { return EC2OSP(public_point(), PointGFp::UNCOMPRESSED); }

      /**
      * Derive a shared key with the other parties public key.
      * @param key the other partys public key
      * @param key_len the other partys public key
      */
      SecureVector<byte> derive_key(const byte key[], u32bit key_len) const;

      /**
      * Derive a shared key with the other parties public key.
      * @param other the other partys public key
      */
      SecureVector<byte> derive_key(const ECDH_PublicKey& other) const;

      /**
      * Derive a shared key with the other parties public key.
      * @param point the public point of the other parties key
      */
      SecureVector<byte> derive_key(const PointGFp& point) const;
   };

}

#endif
