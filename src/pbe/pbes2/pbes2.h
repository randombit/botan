/*
* PKCS #5 v2.0 PBE
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PBE_PKCS_v20_H__
#define BOTAN_PBE_PKCS_v20_H__

#include <botan/pbe.h>
#include <botan/block_cipher.h>
#include <botan/hash.h>
#include <botan/pipe.h>

namespace Botan {

/**
* PKCS #5 v2.0 PBE
*/
class BOTAN_DLL PBE_PKCS5v20 : public PBE
   {
   public:
      /**
      * @param cipher names a block cipher
      * @return true iff PKCS #5 knows how to use this cipher
      */
      static bool known_cipher(const std::string& cipher);

      std::string name() const;

      void write(const byte[], size_t);
      void start_msg();
      void end_msg();

      /**
      * Load a PKCS #5 v2.0 encrypted stream
      * @param input is the input source
      */
      PBE_PKCS5v20(DataSource& input);

      /**
      * @param cipher the block cipher to use
      * @param hash the hash function to use
      */
      PBE_PKCS5v20(BlockCipher* cipher, HashFunction* hash);

      ~PBE_PKCS5v20();
   private:
      void set_key(const std::string&);
      void new_params(RandomNumberGenerator& rng);
      MemoryVector<byte> encode_params() const;
      void decode_params(DataSource&);
      OID get_oid() const;

      void flush_pipe(bool);

      Cipher_Dir direction;
      BlockCipher* block_cipher;
      HashFunction* hash_function;
      SecureVector<byte> salt, key, iv;
      size_t iterations, key_length;
      Pipe pipe;
   };

}

#endif
