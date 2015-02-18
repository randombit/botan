/*
* Passhash9 Password Hashing
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/passhash9.h>
#include <botan/loadstor.h>
#include <botan/lookup.h>
#include <botan/pbkdf2.h>
#include <botan/base64.h>

namespace Botan {

namespace {

const std::string MAGIC_PREFIX = "$9$";

const size_t WORKFACTOR_BYTES = 2;
const size_t ALGID_BYTES = 1;
const size_t SALT_BYTES = 12; // 96 bits of salt
const size_t PASSHASH9_PBKDF_OUTPUT_LEN = 24; // 192 bits output

const size_t WORK_FACTOR_SCALE = 10000;

MessageAuthenticationCode* get_pbkdf_prf(byte alg_id)
   {
   try
      {
      if(alg_id == 0)
         return get_mac("HMAC(SHA-1)");
      else if(alg_id == 1)
         return get_mac("HMAC(SHA-256)");
      else if(alg_id == 2)
         return get_mac("CMAC(Blowfish)");
      else if(alg_id == 3)
         return get_mac("HMAC(SHA-384)");
      else if(alg_id == 4)
         return get_mac("HMAC(SHA-512)");
      }
   catch(Algorithm_Not_Found) {}

   return nullptr;
   }

}

std::string generate_passhash9(const std::string& pass,
                               RandomNumberGenerator& rng,
                               u16bit work_factor,
                               byte alg_id)
   {
   MessageAuthenticationCode* prf = get_pbkdf_prf(alg_id);

   if(!prf)
      throw Invalid_Argument("Passhash9: Algorithm id " +
                             std::to_string(alg_id) +
                             " is not defined");

   PKCS5_PBKDF2 kdf(prf); // takes ownership of pointer

   secure_vector<byte> salt(SALT_BYTES);
   rng.randomize(&salt[0], salt.size());

   const size_t kdf_iterations = WORK_FACTOR_SCALE * work_factor;

   secure_vector<byte> blob;
   blob.push_back(alg_id);
   blob.push_back(get_byte(0, work_factor));
   blob.push_back(get_byte(1, work_factor));
   blob += salt;
   blob += kdf.derive_key(PASSHASH9_PBKDF_OUTPUT_LEN,
                          pass,
                          &salt[0], salt.size(),
                          kdf_iterations).bits_of();

   return MAGIC_PREFIX + base64_encode(blob);
   }

bool check_passhash9(const std::string& pass, const std::string& hash)
   {
   const size_t BINARY_LENGTH =
     ALGID_BYTES +
     WORKFACTOR_BYTES +
     PASSHASH9_PBKDF_OUTPUT_LEN +
     SALT_BYTES;

   const size_t BASE64_LENGTH =
      MAGIC_PREFIX.size() + (BINARY_LENGTH * 8) / 6;

   if(hash.size() != BASE64_LENGTH)
      return false;

   for(size_t i = 0; i != MAGIC_PREFIX.size(); ++i)
      if(hash[i] != MAGIC_PREFIX[i])
         return false;

   secure_vector<byte> bin = base64_decode(hash.c_str() + MAGIC_PREFIX.size());

   if(bin.size() != BINARY_LENGTH)
      return false;

   byte alg_id = bin[0];

   const size_t work_factor = load_be<u16bit>(&bin[ALGID_BYTES], 0);

   // Bug in the format, bad states shouldn't be representable, but are...
   if(work_factor == 0)
      return false;

   if(work_factor > 512)
      throw std::invalid_argument("Requested Bcrypt work factor " +
                                  std::to_string(work_factor) + " too large");

   const size_t kdf_iterations = WORK_FACTOR_SCALE * work_factor;

   MessageAuthenticationCode* pbkdf_prf = get_pbkdf_prf(alg_id);

   if(!pbkdf_prf)
      return false; // unknown algorithm, reject

   PKCS5_PBKDF2 kdf(pbkdf_prf); // takes ownership of pointer

   secure_vector<byte> cmp = kdf.derive_key(
      PASSHASH9_PBKDF_OUTPUT_LEN,
      pass,
      &bin[ALGID_BYTES + WORKFACTOR_BYTES], SALT_BYTES,
      kdf_iterations).bits_of();

   return same_mem(&cmp[0],
                   &bin[ALGID_BYTES + WORKFACTOR_BYTES + SALT_BYTES],
                   PASSHASH9_PBKDF_OUTPUT_LEN);
   }

}
