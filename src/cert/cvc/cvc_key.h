/*
* EAC CVC Public Key
* (C) 2008 FlexSecure Gmbh
*          Falko Strenzke
*          strenzke@flexsecure.de
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EAC1_1_CVC_PUBLIC_KEY_H__
#define BOTAN_EAC1_1_CVC_PUBLIC_KEY_H__

#include <botan/pipe.h>
#include <botan/pk_keys.h>
#include <botan/alg_id.h>

namespace Botan {

/**
* This class represents EAC 1.1 CVC public key encoders.
*/
class BOTAN_DLL EAC1_1_CVC_Encoder
   {
   public:
      /**
      * Get the DER encoded CVC public key.
      * @param alg_id the algorithm identifier to use in the encoding
      * @return the DER encoded public key
      */
      virtual MemoryVector<byte>
         public_key(const AlgorithmIdentifier& enc) const = 0;

      virtual ~EAC1_1_CVC_Encoder() {}
   };

/**
* This class represents EAC 1.1 CVC public key decoders.
*/
class BOTAN_DLL EAC1_1_CVC_Decoder
   {
   public:
      /**
      * Decode a CVC public key.
      * @param enc the DER encoded public key to decode
      * @return the algorithm identifier found in the encoded public key
      */
      virtual AlgorithmIdentifier const
         public_key(const MemoryRegion<byte>& enc) = 0;

      virtual ~EAC1_1_CVC_Decoder() {}
   };
}

#endif
