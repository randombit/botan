/*************************************************
* PKCS PBE Header File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_PBE_PKCS_H__
#define BOTAN_PBE_PKCS_H__

#include <botan/pbe.h>
#include <botan/pipe.h>
#include <botan/enums.h>

namespace Botan {

/*************************************************
* PKCS#5 v1.5 PBE                                *
*************************************************/
class BOTAN_DLL PBE_PKCS5v15 : public PBE
   {
   public:
      void write(const byte[], u32bit);
      void start_msg();
      void end_msg();
      PBE_PKCS5v15(const std::string&, const std::string&, Cipher_Dir);
   private:
      void set_key(const std::string&);
      void new_params(RandomNumberGenerator& rng);
      MemoryVector<byte> encode_params() const;
      void decode_params(DataSource&);
      OID get_oid() const;

      void flush_pipe(bool);
      const Cipher_Dir direction;
      const std::string digest, cipher;
      SecureVector<byte> salt, key, iv;
      u32bit iterations;
      Pipe pipe;
   };

/*************************************************
* PKCS#5 v2.0 PBE                                *
*************************************************/
class BOTAN_DLL PBE_PKCS5v20 : public PBE
   {
   public:
      void write(const byte[], u32bit);
      void start_msg();
      void end_msg();
      PBE_PKCS5v20(DataSource&);
      PBE_PKCS5v20(const std::string&, const std::string&);
   private:
      void set_key(const std::string&);
      void new_params(RandomNumberGenerator& rng);
      MemoryVector<byte> encode_params() const;
      void decode_params(DataSource&);
      OID get_oid() const;

      void flush_pipe(bool);
      bool known_cipher(const std::string&) const;

      const Cipher_Dir direction;
      std::string digest, cipher, cipher_algo;
      SecureVector<byte> salt, key, iv;
      u32bit iterations, key_length;
      Pipe pipe;
   };

}

#endif
