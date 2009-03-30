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

namespace Botan {

/*
* PKCS#5 v1.5 PBE
*/
class BOTAN_DLL PBE_PKCS5v15 : public PBE
   {
   public:
      void write(const byte[], u32bit);
      void start_msg();
      void end_msg();

      PBE_PKCS5v15(BlockCipher* cipher,
                   HashFunction* hash,
                   Cipher_Dir);

      ~PBE_PKCS5v15();
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
      u32bit iterations;
      Pipe pipe;
   };

}

#endif
