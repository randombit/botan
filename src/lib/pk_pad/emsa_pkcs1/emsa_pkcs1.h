/*
* PKCS #1 v1.5 signature padding
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EMSA_PKCS1_H__
#define BOTAN_EMSA_PKCS1_H__

#include <botan/emsa.h>
#include <botan/hash.h>

namespace Botan {

/**
* PKCS #1 v1.5 signature padding
* aka PKCS #1 block type 1
* aka EMSA3 from IEEE 1363
*/
class BOTAN_DLL EMSA_PKCS1v15 final : public EMSA
   {
   public:
      static EMSA* make(const EMSA::Spec& spec);

      /**
      * @param hash the hash object to use
      */
      explicit EMSA_PKCS1v15(HashFunction* hash);

      void update(const byte[], size_t) override;

      secure_vector<byte> raw_data() override;

      secure_vector<byte> encoding_of(const secure_vector<byte>&, size_t,
                                     RandomNumberGenerator& rng) override;

      bool verify(const secure_vector<byte>&, const secure_vector<byte>&,
                  size_t) override;
   private:
      std::unique_ptr<HashFunction> m_hash;
      std::vector<byte> m_hash_id;
   };

/**
* EMSA_PKCS1v15_Raw which is EMSA_PKCS1v15 without a hash or digest id
* (which according to QCA docs is "identical to PKCS#11's CKM_RSA_PKCS
* mechanism", something I have not confirmed)
*/
class BOTAN_DLL EMSA_PKCS1v15_Raw final : public EMSA
   {
   public:
      void update(const byte[], size_t) override;

      secure_vector<byte> raw_data() override;

      secure_vector<byte> encoding_of(const secure_vector<byte>&, size_t,
                                     RandomNumberGenerator& rng) override;

      bool verify(const secure_vector<byte>&, const secure_vector<byte>&,
                  size_t) override;

   private:
      secure_vector<byte> m_message;
   };

}

#endif
