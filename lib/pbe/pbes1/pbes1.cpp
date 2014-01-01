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
#include <botan/lookup.h>
#include <algorithm>

namespace Botan {

/*
* Encrypt some bytes using PBES1
*/
void PBE_PKCS5v15::write(const byte input[], size_t length)
   {
   m_pipe.write(input, length);
   flush_pipe(true);
   }

/*
* Start encrypting with PBES1
*/
void PBE_PKCS5v15::start_msg()
   {
   m_pipe.append(get_cipher(m_block_cipher->name() + "/CBC/PKCS7",
                            m_key, m_iv, m_direction));

   m_pipe.start_msg();
   if(m_pipe.message_count() > 1)
      m_pipe.set_default_msg(m_pipe.default_msg() + 1);
   }

/*
* Finish encrypting with PBES1
*/
void PBE_PKCS5v15::end_msg()
   {
   m_pipe.end_msg();
   flush_pipe(false);
   m_pipe.reset();
   }

/*
* Flush the pipe
*/
void PBE_PKCS5v15::flush_pipe(bool safe_to_skip)
   {
   if(safe_to_skip && m_pipe.remaining() < 64)
      return;

   secure_vector<byte> buffer(DEFAULT_BUFFERSIZE);
   while(m_pipe.remaining())
      {
      size_t got = m_pipe.read(&buffer[0], buffer.size());
      send(buffer, got);
      }
   }

/*
* Encode PKCS#5 PBES1 parameters
*/
std::vector<byte> PBE_PKCS5v15::encode_params() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode(m_salt, OCTET_STRING)
         .encode(m_iterations)
      .end_cons()
   .get_contents_unlocked();
   }

/*
* Return an OID for this PBES1 type
*/
OID PBE_PKCS5v15::get_oid() const
   {
   const OID base_pbes1_oid("1.2.840.113549.1.5");

   const std::string cipher = m_block_cipher->name();
   const std::string digest = m_hash_function->name();

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

std::string PBE_PKCS5v15::name() const
   {
   return "PBE-PKCS5v15(" + m_block_cipher->name() + "," +
                            m_hash_function->name() + ")";
   }

PBE_PKCS5v15::PBE_PKCS5v15(BlockCipher* cipher,
                           HashFunction* hash,
                           const std::string& passphrase,
                           std::chrono::milliseconds msec,
                           RandomNumberGenerator& rng) :
   m_direction(ENCRYPTION),
   m_block_cipher(cipher),
   m_hash_function(hash),
   m_salt(rng.random_vec(8))
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

   PKCS5_PBKDF1 pbkdf(m_hash_function->clone());

   secure_vector<byte> key_and_iv =
      pbkdf.derive_key(16, passphrase,
                       &m_salt[0], m_salt.size(),
                       msec, m_iterations).bits_of();

   m_key.assign(&key_and_iv[0], &key_and_iv[8]);
   m_iv.assign(&key_and_iv[8], &key_and_iv[16]);

   }

PBE_PKCS5v15::PBE_PKCS5v15(BlockCipher* cipher,
                           HashFunction* hash,
                           const std::vector<byte>& params,
                           const std::string& passphrase) :
   m_direction(DECRYPTION),
   m_block_cipher(cipher),
   m_hash_function(hash)
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

   BER_Decoder(params)
      .start_cons(SEQUENCE)
         .decode(m_salt, OCTET_STRING)
         .decode(m_iterations)
         .verify_end()
      .end_cons();

   if(m_salt.size() != 8)
      throw Decoding_Error("PBES1: Encoded salt is not 8 octets");

   PKCS5_PBKDF1 pbkdf(m_hash_function->clone());

   secure_vector<byte> key_and_iv =
      pbkdf.derive_key(16, passphrase,
                       &m_salt[0], m_salt.size(),
                       m_iterations).bits_of();

   m_key.assign(&key_and_iv[0], &key_and_iv[8]);
   m_iv.assign(&key_and_iv[8], &key_and_iv[16]);
   }

PBE_PKCS5v15::~PBE_PKCS5v15()
   {
   delete m_block_cipher;
   delete m_hash_function;
   }

}
