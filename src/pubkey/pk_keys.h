/*
* PK Key Types
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PK_KEYS_H__
#define BOTAN_PK_KEYS_H__

#include <botan/secmem.h>
#include <botan/asn1_oid.h>
#include <botan/alg_id.h>
#include <botan/rng.h>

namespace Botan {

/**
* Public Key Base Class.
*/
class BOTAN_DLL Public_Key
   {
   public:
      /**
      * Get the name of the underlying public key scheme.
      * @return the name of the public key scheme
      */
      virtual std::string algo_name() const = 0;

      /**
      * Get the OID of the underlying public key scheme.
      * @return the OID of the public key scheme
      */
      virtual OID get_oid() const;

      /**
      * Test the key values for consistency.
      * @param rng rng to use
      * @param strong whether to perform strong and lengthy version
      * of the test
      * @return true if the test is passed
      */
      virtual bool check_key(RandomNumberGenerator&, bool) const
         { return true; }

      /**
      * Find out the number of message parts supported by this scheme.
      * @return the number of message parts
      */
      virtual u32bit message_parts() const { return 1; }

      /**
      * Find out the message part size supported by this scheme/key.
      * @return the size of the message parts
      */
      virtual u32bit message_part_size() const { return 0; }

      /**
      * Get the maximum message size in bits supported by this public key.
      * @return the maximum message in bits
      */
      virtual u32bit max_input_bits() const = 0;

      /**
      * @return X.509 AlgorithmIdentifier for this key
      */
      virtual AlgorithmIdentifier algorithm_identifier() const = 0;

      /**
      * @return X.509 subject key encoding for this key object
      */
      virtual MemoryVector<byte> x509_subject_public_key() const = 0;

      virtual ~Public_Key() {}
   protected:
      virtual void load_check(RandomNumberGenerator&) const;
   };

/**
* Private Key Base Class
*/
class BOTAN_DLL Private_Key : public virtual Public_Key
   {
   public:
      /**
      * @return PKCS #8 private key encoding for this key object
      */
      virtual MemoryVector<byte> pkcs8_private_key() const = 0;

      /**
      * @return PKCS #8 AlgorithmIdentifier for this key
      * Might be different from the X.509 identifier, but normally is not
      */
      virtual AlgorithmIdentifier pkcs8_algorithm_identifier() const
         { return algorithm_identifier(); }

   protected:
      void load_check(RandomNumberGenerator&) const;
      void gen_check(RandomNumberGenerator&) const;
   };

/**
* PK Secret Value Derivation Key
*/
class BOTAN_DLL PK_Key_Agreement_Key : public virtual Private_Key
   {
   public:
      virtual MemoryVector<byte> public_value() const = 0;

      virtual ~PK_Key_Agreement_Key() {}
   };

/*
* Typedefs
*/
typedef PK_Key_Agreement_Key PK_KA_Key;
typedef Public_Key X509_PublicKey;
typedef Private_Key PKCS8_PrivateKey;

}

#endif
