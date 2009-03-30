/*
* PKCS #5 PBES1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pbes1.h>
#include <botan/pbkdf1.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/cbc.h>
#include <algorithm>

namespace Botan {

/*
* Encrypt some bytes using PBES1
*/
void PBE_PKCS5v15::write(const byte input[], u32bit length)
   {
   while(length)
      {
      u32bit put = std::min(DEFAULT_BUFFERSIZE, length);
      pipe.write(input, length);
      flush_pipe(true);
      length -= put;
      }
   }

/*
* Start encrypting with PBES1
*/
void PBE_PKCS5v15::start_msg()
   {
   if(direction == ENCRYPTION)
      pipe.append(new CBC_Encryption(block_cipher->clone(),
                                     new PKCS7_Padding,
                                     key, iv));
   else
      pipe.append(new CBC_Decryption(block_cipher->clone(),
                                     new PKCS7_Padding,
                                     key, iv));

   pipe.start_msg();
   if(pipe.message_count() > 1)
      pipe.set_default_msg(pipe.default_msg() + 1);
   }

/*
* Finish encrypting with PBES1
*/
void PBE_PKCS5v15::end_msg()
   {
   pipe.end_msg();
   flush_pipe(false);
   pipe.reset();
   }

/*
* Flush the pipe
*/
void PBE_PKCS5v15::flush_pipe(bool safe_to_skip)
   {
   if(safe_to_skip && pipe.remaining() < 64)
      return;

   SecureVector<byte> buffer(DEFAULT_BUFFERSIZE);
   while(pipe.remaining())
      {
      u32bit got = pipe.read(buffer, buffer.size());
      send(buffer, got);
      }
   }

/*
* Set the passphrase to use
*/
void PBE_PKCS5v15::set_key(const std::string& passphrase)
   {
   PKCS5_PBKDF1 pbkdf(hash_function->clone());

   pbkdf.set_iterations(iterations);
   pbkdf.change_salt(salt, salt.size());
   SymmetricKey key_and_iv = pbkdf.derive_key(16, passphrase);

   key.set(key_and_iv.begin(), 8);
   iv.set(key_and_iv.begin() + 8, 8);
   }

/*
* Create a new set of PBES1 parameters
*/
void PBE_PKCS5v15::new_params(RandomNumberGenerator& rng)
   {
   iterations = 2048;
   salt.create(8);
   rng.randomize(salt, salt.size());
   }

/*
* Encode PKCS#5 PBES1 parameters
*/
MemoryVector<byte> PBE_PKCS5v15::encode_params() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode(salt, OCTET_STRING)
         .encode(iterations)
      .end_cons()
   .get_contents();
   }

/*
* Decode PKCS#5 PBES1 parameters
*/
void PBE_PKCS5v15::decode_params(DataSource& source)
   {
   BER_Decoder(source)
      .start_cons(SEQUENCE)
         .decode(salt, OCTET_STRING)
         .decode(iterations)
         .verify_end()
      .end_cons();

   if(salt.size() != 8)
      throw Decoding_Error("PBES1: Encoded salt is not 8 octets");
   }

/*
* Return an OID for this PBES1 type
*/
OID PBE_PKCS5v15::get_oid() const
   {
   const OID base_pbes1_oid("1.2.840.113549.1.5");

   const std::string cipher = block_cipher->name();
   const std::string digest = hash_function->name();

   if(cipher == "DES" && digest == "MD2")
      return (base_pbes1_oid + 1);
   else if(cipher == "DES" && digest == "MD5")
      return (base_pbes1_oid + 3);
   else if(cipher == "DES" && digest == "SHA-160")
      return (base_pbes1_oid + 10);
   else if(cipher == "RC2" && digest == "MD2")
      return (base_pbes1_oid + 4);
   else if(cipher == "RC2" && digest == "MD5")
      return (base_pbes1_oid + 6);
   else if(cipher == "RC2" && digest == "SHA-160")
      return (base_pbes1_oid + 11);
   else
      throw Internal_Error("PBE-PKCS5 v1.5: get_oid() has run out of options");
   }

/*
* PKCS#5 v1.5 PBE Constructor
*/
PBE_PKCS5v15::PBE_PKCS5v15(BlockCipher* cipher,
                           HashFunction* hash,
                           Cipher_Dir dir) :
   direction(dir), block_cipher(cipher), hash_function(hash)
   {
   if(cipher->name() != "DES" && cipher->name() != "RC2")
      {
      throw Invalid_Argument("PBE_PKCS5v1.5: Unknown cipher " +
                             cipher->name());
      }

   if(hash->name() != "MD2" && hash->name() != "MD5" &&
      hash->name() != "SHA-160")
      {
      throw Invalid_Argument("PBE_PKCS5v1.5: Unknown hash " +
                             hash->name());
      }
   }

PBE_PKCS5v15::~PBE_PKCS5v15()
   {
   delete block_cipher;
   delete hash_function;
   }

}
