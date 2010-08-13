/**
* PKCS #5 PBES2
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pbes2.h>
#include <botan/pbkdf2.h>
#include <botan/hmac.h>
#include <botan/cbc.h>
#include <botan/algo_factory.h>
#include <botan/libstate.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/parsing.h>
#include <botan/asn1_obj.h>
#include <botan/oids.h>
#include <algorithm>
#include <memory>

namespace Botan {

/**
* Encrypt some bytes using PBES2
*/
void PBE_PKCS5v20::write(const byte input[], u32bit length)
   {
   while(length)
      {
      u32bit put = std::min(DEFAULT_BUFFERSIZE, length);
      pipe.write(input, length);
      flush_pipe(true);
      length -= put;
      }
   }

/**
* Start encrypting with PBES2
*/
void PBE_PKCS5v20::start_msg()
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

/**
* Finish encrypting with PBES2
*/
void PBE_PKCS5v20::end_msg()
   {
   pipe.end_msg();
   flush_pipe(false);
   pipe.reset();
   }

/**
* Flush the pipe
*/
void PBE_PKCS5v20::flush_pipe(bool safe_to_skip)
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

/**
* Set the passphrase to use
*/
void PBE_PKCS5v20::set_key(const std::string& passphrase)
   {
   PKCS5_PBKDF2 pbkdf(new HMAC(hash_function->clone()));

   pbkdf.set_iterations(iterations);
   pbkdf.change_salt(salt, salt.size());
   key = pbkdf.derive_key(key_length, passphrase).bits_of();
   }

/**
* Create a new set of PBES2 parameters
*/
void PBE_PKCS5v20::new_params(RandomNumberGenerator& rng)
   {
   iterations = 10000;
   key_length = block_cipher->MAXIMUM_KEYLENGTH;

   salt.create(8);
   rng.randomize(salt, salt.size());

   iv.create(block_cipher->BLOCK_SIZE);
   rng.randomize(iv, iv.size());
   }

/**
* Encode PKCS#5 PBES2 parameters
*/
MemoryVector<byte> PBE_PKCS5v20::encode_params() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
      .encode(
         AlgorithmIdentifier("PKCS5.PBKDF2",
            DER_Encoder()
               .start_cons(SEQUENCE)
                  .encode(salt, OCTET_STRING)
                  .encode(iterations)
                  .encode(key_length)
               .end_cons()
            .get_contents()
            )
         )
      .encode(
         AlgorithmIdentifier(block_cipher->name() + "/CBC",
            DER_Encoder()
               .encode(iv, OCTET_STRING)
            .get_contents()
            )
         )
      .end_cons()
      .get_contents();
   }

/**
* Decode PKCS#5 PBES2 parameters
*/
void PBE_PKCS5v20::decode_params(DataSource& source)
   {
   AlgorithmIdentifier kdf_algo, enc_algo;

   BER_Decoder(source)
      .start_cons(SEQUENCE)
         .decode(kdf_algo)
         .decode(enc_algo)
         .verify_end()
      .end_cons();

   if(kdf_algo.oid == OIDS::lookup("PKCS5.PBKDF2"))
      {
      BER_Decoder(kdf_algo.parameters)
         .start_cons(SEQUENCE)
            .decode(salt, OCTET_STRING)
            .decode(iterations)
            .decode_optional(key_length, INTEGER, UNIVERSAL)
            .verify_end()
         .end_cons();
      }
   else
      throw Decoding_Error("PBE-PKCS5 v2.0: Unknown KDF algorithm " +
                           kdf_algo.oid.as_string());

   Algorithm_Factory& af = global_state().algorithm_factory();

   std::string cipher = OIDS::lookup(enc_algo.oid);
   std::vector<std::string> cipher_spec = split_on(cipher, '/');
   if(cipher_spec.size() != 2)
      throw Decoding_Error("PBE-PKCS5 v2.0: Invalid cipher spec " + cipher);

   if(!known_cipher(cipher_spec[0]) || cipher_spec[1] != "CBC")
      throw Decoding_Error("PBE-PKCS5 v2.0: Don't know param format for " +
                           cipher);

   BER_Decoder(enc_algo.parameters).decode(iv, OCTET_STRING).verify_end();

   block_cipher = af.make_block_cipher(cipher_spec[0]);
   hash_function = af.make_hash_function("SHA-160");

   if(key_length == 0)
      key_length = block_cipher->MAXIMUM_KEYLENGTH;

   if(salt.size() < 8)
      throw Decoding_Error("PBE-PKCS5 v2.0: Encoded salt is too small");
   }

/**
* Return an OID for PBES2
*/
OID PBE_PKCS5v20::get_oid() const
   {
   return OIDS::lookup("PBE-PKCS5v20");
   }

/**
* Check if this is a known PBES2 cipher
*/
bool PBE_PKCS5v20::known_cipher(const std::string& algo)
   {
   if(algo == "AES-128" || algo == "AES-192" || algo == "AES-256")
      return true;
   if(algo == "DES" || algo == "TripleDES")
      return true;
   return false;
   }

/**
* PKCS#5 v2.0 PBE Constructor
*/
PBE_PKCS5v20::PBE_PKCS5v20(BlockCipher* cipher,
                           HashFunction* digest) :
   direction(ENCRYPTION), block_cipher(cipher), hash_function(digest)
   {
   if(!known_cipher(block_cipher->name()))
      throw Invalid_Argument("PBE-PKCS5 v2.0: Invalid cipher " + cipher->name());
   if(hash_function->name() != "SHA-160")
      throw Invalid_Argument("PBE-PKCS5 v2.0: Invalid digest " + digest->name());
   }

/**
* PKCS#5 v2.0 PBE Constructor
*/
PBE_PKCS5v20::PBE_PKCS5v20(DataSource& params) : direction(DECRYPTION)
   {
   hash_function = 0;
   block_cipher = 0;
   decode_params(params);
   }

PBE_PKCS5v20::~PBE_PKCS5v20()
   {
   delete hash_function;
   delete block_cipher;
   }

}
