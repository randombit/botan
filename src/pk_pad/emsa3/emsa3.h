/*
* EMSA3 and EMSA3_Raw
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EMSA3_H__
#define BOTAN_EMSA3_H__

#include <botan/emsa.h>
#include <botan/hash.h>

namespace Botan {

/**
* EMSA3 from IEEE 1363
* aka PKCS #1 v1.5 signature padding
* aka PKCS #1 block type 1
*/
class BOTAN_DLL EMSA3 : public EMSA
   {
   public:
      /**
      * @param hash the hash object to use
      */
      EMSA3(HashFunction* hash);
      ~EMSA3();

      void update(const byte[], size_t);

      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, size_t,
                                     RandomNumberGenerator& rng);

      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  size_t);
   private:
      HashFunction* hash;
      SecureVector<byte> hash_id;
   };

/**
* EMSA3_Raw which is EMSA3 without a hash or digest id (which
* according to QCA docs is "identical to PKCS#11's CKM_RSA_PKCS
* mechanism", something I have not confirmed)
*/
class BOTAN_DLL EMSA3_Raw : public EMSA
   {
   public:
      void update(const byte[], size_t);

      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, size_t,
                                     RandomNumberGenerator& rng);

      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  size_t);

   private:
      SecureVector<byte> message;
   };

}

#endif
