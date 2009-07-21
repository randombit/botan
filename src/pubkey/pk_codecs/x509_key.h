/*
* X.509 Public Key
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_X509_PUBLIC_KEY_H__
#define BOTAN_X509_PUBLIC_KEY_H__

#include <botan/pipe.h>
#include <botan/pk_keys.h>
#include <botan/alg_id.h>
#include <botan/pubkey_enums.h>

namespace Botan {

/**
* This class represents abstract X.509 public key encoders.
*/
class BOTAN_DLL X509_Encoder
   {
   public:
      virtual AlgorithmIdentifier alg_id() const = 0;
      virtual MemoryVector<byte> key_bits() const = 0;
      virtual ~X509_Encoder() {}
   };

/**
* This class represents abstract X.509 public key decoders.
*/
class BOTAN_DLL X509_Decoder
   {
   public:
      virtual void alg_id(const AlgorithmIdentifier&) = 0;
      virtual void key_bits(const MemoryRegion<byte>&) = 0;
      virtual ~X509_Decoder() {}
   };

/**
* This namespace contains functions for handling X509 objects.
*/
namespace X509 {

/*
* X.509 Public Key Encoding/Decoding
*/

/**
* Encode a key into a pipe.
* @param key the public key to encode
* @param pipe the pipe to feed the encoded key into
* @param enc the encoding type to use
*/
BOTAN_DLL void encode(const Public_Key& key, Pipe& pipe,
                      X509_Encoding enc = PEM);

/**
* PEM encode a public key into a string.
* @param key the key to encode
* @return the PEM encoded key
*/
BOTAN_DLL std::string PEM_encode(const Public_Key& key);

/**
* Create a public key from a data source.
* @param source the source providing the DER or PEM encoded key
* @return the new public key object
*/
BOTAN_DLL Public_Key* load_key(DataSource& source);

/**
* Create a public key from a string.
* @param enc the string containing the PEM encoded key
* @return the new public key object
*/
BOTAN_DLL Public_Key* load_key(const std::string& enc);

/**
* Create a public key from a memory region.
* @param enc the memory region containing the DER or PEM encoded key
* @return the new public key object
*/
BOTAN_DLL Public_Key* load_key(const MemoryRegion<byte>& enc);

/**
* Copy a key.
* @param key the public key to copy
* @return the new public key object
*/
BOTAN_DLL Public_Key* copy_key(const Public_Key& key);

/**
* Create the key constraints for a specific public key.
* @param pub_key the public key from which the basic set of
* constraints to be placed in the return value is derived
* @param limits additional limits that will be incorporated into the
* return value
* @return the combination of key type specific constraints and
* additional limits
*/

BOTAN_DLL Key_Constraints find_constraints(const Public_Key& pub_key,
                                           Key_Constraints limits);

}

}

#endif
