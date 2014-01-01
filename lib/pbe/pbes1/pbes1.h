/*
* PKCS #5 v1.5 PBE
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PBE_PKCS_V15_H__
#define BOTAN_PBE_PKCS_V15_H__

#include <botan/pbe.h>
#include <botan/block_cipher.h>
#include <botan/hash.h>
#include <botan/pipe.h>
#include <chrono>

namespace Botan {

/**
* PKCS #5 v1.5 PBE
*/
class BOTAN_DLL PBE_PKCS5v15 : public PBE
   {
   public:
      OID get_oid() const;

      std::vector<byte> encode_params() const;

      std::string name() const;

      void write(const byte[], size_t);
      void start_msg();
      void end_msg();

      /**
      * @param cipher the block cipher to use (DES or RC2)
      * @param hash the hash function to use
      * @param passphrase the passphrase to use
      * @param msec how many milliseconds to run the PBKDF
      * @param rng a random number generator
      */
      PBE_PKCS5v15(BlockCipher* cipher,
                   HashFunction* hash,
                   const std::string& passphrase,
                   std::chrono::milliseconds msec,
                   RandomNumberGenerator& rng);

      PBE_PKCS5v15(BlockCipher* cipher,
                   HashFunction* hash,
                   const std::vector<byte>& params,
                   const std::string& passphrase);

      ~PBE_PKCS5v15();
   private:

      void flush_pipe(bool);

      Cipher_Dir m_direction;
      BlockCipher* m_block_cipher;
      HashFunction* m_hash_function;

      secure_vector<byte> m_salt, m_key, m_iv;
      size_t m_iterations;
      Pipe m_pipe;
   };

}

#endif
