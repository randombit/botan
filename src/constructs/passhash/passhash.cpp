/*
* Password Hashing
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/passhash.h>
#include <botan/loadstor.h>
#include <botan/libstate.h>
#include <botan/pbkdf2.h>
#include <botan/base64.h>
#include <botan/pipe.h>

namespace Botan {

namespace {

const std::string MAGIC_PREFIX = "$9$";
const u32bit SALT_BYTES = 10; // 80 bits of salt
const u32bit PBKDF_OUTPUT_LEN = 15; // 112 bits output
const u32bit WORK_FACTOR_SCALE = 10000;
const std::string PBKDF_MAC = "HMAC(SHA-1)";

}

std::string password_hash(const std::string& pass,
                          RandomNumberGenerator& rng,
                          u16bit work_factor)
   {
   PKCS5_PBKDF2 kdf(
      global_state().algorithm_factory().make_mac(PBKDF_MAC)
      );

   SecureVector<byte> salt(SALT_BYTES);
   rng.randomize(&salt[0], salt.size());

   u32bit kdf_iterations = WORK_FACTOR_SCALE * work_factor;

   SecureVector<byte> pbkdf2_output =
      kdf.derive_key(PBKDF_OUTPUT_LEN, pass,
                     &salt[0], salt.size(),
                     kdf_iterations).bits_of();

   Pipe pipe(new Base64_Encoder);
   pipe.start_msg();
   pipe.write(get_byte(0, work_factor));
   pipe.write(get_byte(1, work_factor));
   pipe.write(salt);
   pipe.write(pbkdf2_output);
   pipe.end_msg();

   return MAGIC_PREFIX + pipe.read_all_as_string();
   }

bool password_hash_ok(const std::string& pass, const std::string& hash)
   {
   if(hash.size() != (36 + MAGIC_PREFIX.size()))
      return false;

   for(size_t i = 0; i != MAGIC_PREFIX.size(); ++i)
      if(hash[i] != MAGIC_PREFIX[i])
         return false;

   Pipe pipe(new Base64_Decoder);
   pipe.start_msg();
   pipe.write(hash.c_str() + MAGIC_PREFIX.size());
   pipe.end_msg();

   SecureVector<byte> bin = pipe.read_all();

   const u32bit WORKFACTOR_BYTES = 2;

   if(bin.size() != (WORKFACTOR_BYTES + PBKDF_OUTPUT_LEN + SALT_BYTES))
      return false;

   u32bit kdf_iterations = WORK_FACTOR_SCALE * load_be<u16bit>(bin, 0);

   if(kdf_iterations == 0)
      return false;

   PKCS5_PBKDF2 kdf(
      global_state().algorithm_factory().make_mac(PBKDF_MAC)
      );

   SecureVector<byte> cmp = kdf.derive_key(
      PBKDF_OUTPUT_LEN, pass,
      &bin[WORKFACTOR_BYTES], SALT_BYTES,
      kdf_iterations).bits_of();

   return same_mem(cmp.begin(),
                   bin.begin() + WORKFACTOR_BYTES + SALT_BYTES,
                   PBKDF_OUTPUT_LEN);
   }

}
