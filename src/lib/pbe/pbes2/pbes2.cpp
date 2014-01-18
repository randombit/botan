/*
* PKCS #5 PBES2
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pbes2.h>
#include <botan/pbkdf2.h>
#include <botan/algo_factory.h>
#include <botan/libstate.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/parsing.h>
#include <botan/alg_id.h>
#include <botan/oids.h>
#include <botan/lookup.h>
#include <algorithm>

namespace Botan {

/*
* Encrypt some bytes using PBES2
*/
void PBE_PKCS5v20::write(const byte input[], size_t length)
   {
   pipe.write(input, length);
   flush_pipe(true);
   }

/*
* Start encrypting with PBES2
*/
void PBE_PKCS5v20::start_msg()
   {
   pipe.append(get_cipher(block_cipher->name() + "/CBC/PKCS7",
                          key, iv, direction));

   pipe.start_msg();
   if(pipe.message_count() > 1)
      pipe.set_default_msg(pipe.default_msg() + 1);
   }

/*
* Finish encrypting with PBES2
*/
void PBE_PKCS5v20::end_msg()
   {
   pipe.end_msg();
   flush_pipe(false);
   pipe.reset();
   }

/*
* Flush the pipe
*/
void PBE_PKCS5v20::flush_pipe(bool safe_to_skip)
   {
   if(safe_to_skip && pipe.remaining() < 64)
      return;

   secure_vector<byte> buffer(DEFAULT_BUFFERSIZE);
   while(pipe.remaining())
      {
      const size_t got = pipe.read(&buffer[0], buffer.size());
      send(buffer, got);
      }
   }

/*
* Encode PKCS#5 PBES2 parameters
*/
std::vector<byte> PBE_PKCS5v20::encode_params() const
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
                  .encode_if(
                     m_prf->name() != "HMAC(SHA-160)",
                     AlgorithmIdentifier(m_prf->name(),
                                         AlgorithmIdentifier::USE_NULL_PARAM))
               .end_cons()
            .get_contents_unlocked()
            )
         )
      .encode(
         AlgorithmIdentifier(block_cipher->name() + "/CBC",
            DER_Encoder().encode(iv, OCTET_STRING).get_contents_unlocked()
            )
         )
      .end_cons()
      .get_contents_unlocked();
   }

/*
* Return an OID for PBES2
*/
OID PBE_PKCS5v20::get_oid() const
   {
   return OIDS::lookup("PBE-PKCS5v20");
   }

std::string PBE_PKCS5v20::name() const
   {
   return "PBE-PKCS5v20(" + block_cipher->name() + "," +
                            m_prf->name() + ")";
   }

/*
* PKCS#5 v2.0 PBE Constructor
*/
PBE_PKCS5v20::PBE_PKCS5v20(BlockCipher* cipher,
                           MessageAuthenticationCode* mac,
                           const std::string& passphrase,
                           std::chrono::milliseconds msec,
                           RandomNumberGenerator& rng) :
   direction(ENCRYPTION),
   block_cipher(cipher),
   m_prf(mac),
   salt(rng.random_vec(12)),
   iv(rng.random_vec(block_cipher->block_size())),
   iterations(0),
   key_length(block_cipher->maximum_keylength())
   {
   PKCS5_PBKDF2 pbkdf(m_prf->clone());

   key = pbkdf.derive_key(key_length, passphrase,
                          &salt[0], salt.size(),
                          msec, iterations).bits_of();
   }

/*
* PKCS#5 v2.0 PBE Constructor
*/
PBE_PKCS5v20::PBE_PKCS5v20(const std::vector<byte>& params,
                           const std::string& passphrase) :
   direction(DECRYPTION),
   block_cipher(nullptr),
   m_prf(nullptr)
   {
   AlgorithmIdentifier kdf_algo, enc_algo;

   BER_Decoder(params)
      .start_cons(SEQUENCE)
         .decode(kdf_algo)
         .decode(enc_algo)
         .verify_end()
      .end_cons();

   AlgorithmIdentifier prf_algo;

   if(kdf_algo.oid != OIDS::lookup("PKCS5.PBKDF2"))
      throw Decoding_Error("PBE-PKCS5 v2.0: Unknown KDF algorithm " +
                           kdf_algo.oid.as_string());

   BER_Decoder(kdf_algo.parameters)
      .start_cons(SEQUENCE)
         .decode(salt, OCTET_STRING)
         .decode(iterations)
         .decode_optional(key_length, INTEGER, UNIVERSAL)
         .decode_optional(prf_algo, SEQUENCE, CONSTRUCTED,
                          AlgorithmIdentifier("HMAC(SHA-160)",
                                              AlgorithmIdentifier::USE_NULL_PARAM))
      .verify_end()
      .end_cons();

   Algorithm_Factory& af = global_state().algorithm_factory();

   std::string cipher = OIDS::lookup(enc_algo.oid);
   std::vector<std::string> cipher_spec = split_on(cipher, '/');
   if(cipher_spec.size() != 2)
      throw Decoding_Error("PBE-PKCS5 v2.0: Invalid cipher spec " + cipher);

   if(cipher_spec[1] != "CBC")
      throw Decoding_Error("PBE-PKCS5 v2.0: Don't know param format for " +
                           cipher);

   BER_Decoder(enc_algo.parameters).decode(iv, OCTET_STRING).verify_end();

   block_cipher = af.make_block_cipher(cipher_spec[0]);
   m_prf = af.make_mac(OIDS::lookup(prf_algo.oid));

   if(key_length == 0)
      key_length = block_cipher->maximum_keylength();

   if(salt.size() < 8)
      throw Decoding_Error("PBE-PKCS5 v2.0: Encoded salt is too small");

   PKCS5_PBKDF2 pbkdf(m_prf->clone());

   key = pbkdf.derive_key(key_length, passphrase,
                          &salt[0], salt.size(),
                          iterations).bits_of();
   }

PBE_PKCS5v20::~PBE_PKCS5v20()
   {
   delete m_prf;
   delete block_cipher;
   }

}
