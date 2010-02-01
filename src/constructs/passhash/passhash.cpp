/*
* Password Hashing
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/passhash.h>
#include <botan/pbkdf2.h>
#include <botan/hmac.h>
#include <botan/sha2_64.h>
#include <botan/base64.h>
#include <botan/pipe.h>

namespace Botan {

namespace {

const u32bit SALT_BYTES = 8; // 64 bits of salt
const u32bit PBKDF_OUTPUT_LEN = 15; // 112 bits output
const u32bit WORK_FACTOR_SCALE = 10000;

}

std::string password_hash(const std::string& pass,
                          RandomNumberGenerator& rng,
                          byte work_factor)
   {
   PKCS5_PBKDF2 kdf(new HMAC(new SHA_512));

   SecureVector<byte> salt(SALT_BYTES);
   rng.randomize(&salt[0], salt.size());

   u32bit kdf_iterations = WORK_FACTOR_SCALE * work_factor;

   SecureVector<byte> pbkdf2_output =
      kdf.derive_key(PBKDF_OUTPUT_LEN, pass,
                     &salt[0], salt.size(),
                     kdf_iterations).bits_of();

   Pipe pipe(new Base64_Encoder);
   pipe.start_msg();
   pipe.write(work_factor);
   pipe.write(salt);
   pipe.write(pbkdf2_output);
   pipe.end_msg();

   return pipe.read_all_as_string();
   }

bool password_hash_ok(const std::string& pass, const std::string& hash)
   {
   Pipe pipe(new Base64_Decoder);
   pipe.start_msg();
   pipe.write(hash);
   pipe.end_msg();

   SecureVector<byte> bin = pipe.read_all();

   if(bin.size() != (1 + PBKDF_OUTPUT_LEN + SALT_BYTES))
      return false;

   u32bit kdf_iterations = WORK_FACTOR_SCALE * bin[0];

   if(kdf_iterations == 0)
      return false;

   PKCS5_PBKDF2 kdf(new HMAC(new SHA_512));

   SecureVector<byte> cmp = kdf.derive_key(
      PBKDF_OUTPUT_LEN, pass,
      &bin[1], SALT_BYTES,
      kdf_iterations).bits_of();

   return same_mem(cmp.begin(),
                   bin.begin() + 1 + SALT_BYTES,
                   PBKDF_OUTPUT_LEN);
   }

}
