/*
* Passhash9 Password Hashing
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/passhash9.h>
#include <botan/loadstor.h>
#include <botan/libstate.h>
#include <botan/pbkdf2.h>
#include <botan/base64.h>
#include <botan/pipe.h>

namespace Botan {

namespace {

const std::string MAGIC_PREFIX = "$9$";

const u32bit WORKFACTOR_BYTES = 2;
const u32bit ALGID_BYTES = 1;
const u32bit SALT_BYTES = 12; // 96 bits of salt
const u32bit PBKDF_OUTPUT_LEN = 24; // 192 bits output

const u32bit WORK_FACTOR_SCALE = 10000;

MessageAuthenticationCode* get_pbkdf_prf(byte alg_id)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   if(alg_id == 0)
      return af.make_mac("HMAC(SHA-1)");

   return 0;
   }

std::pair<byte, MessageAuthenticationCode*> choose_pbkdf_prf()
   {
   for(byte alg_id = 0; alg_id != 255; ++alg_id)
      {
      MessageAuthenticationCode* prf = get_pbkdf_prf(alg_id);
      if(prf)
         return std::make_pair(alg_id, prf);
      }

   throw Internal_Error("Passhash9: No PRF available");
   }

}

std::string generate_passhash9(const std::string& pass,
                               RandomNumberGenerator& rng,
                               u16bit work_factor)
   {
   std::pair<byte, MessageAuthenticationCode*> prf = choose_pbkdf_prf();
   byte alg_id = prf.first;

   PKCS5_PBKDF2 kdf(prf.second); // takes ownership of pointer

   SecureVector<byte> salt(SALT_BYTES);
   rng.randomize(&salt[0], salt.size());

   u32bit kdf_iterations = WORK_FACTOR_SCALE * work_factor;

   SecureVector<byte> pbkdf2_output =
      kdf.derive_key(PBKDF_OUTPUT_LEN, pass,
                     &salt[0], salt.size(),
                     kdf_iterations).bits_of();

   Pipe pipe(new Base64_Encoder);
   pipe.start_msg();
   pipe.write(alg_id);
   pipe.write(get_byte(0, work_factor));
   pipe.write(get_byte(1, work_factor));
   pipe.write(salt);
   pipe.write(pbkdf2_output);
   pipe.end_msg();

   return MAGIC_PREFIX + pipe.read_all_as_string();
   }

bool check_passhash9(const std::string& pass, const std::string& hash)
   {
   const u32bit BINARY_LENGTH =
      (ALGID_BYTES + WORKFACTOR_BYTES + PBKDF_OUTPUT_LEN + SALT_BYTES);

   const u32bit BASE64_LENGTH =
      MAGIC_PREFIX.size() + (BINARY_LENGTH * 8) / 6;

   if(hash.size() != BASE64_LENGTH)
      return false;

   for(size_t i = 0; i != MAGIC_PREFIX.size(); ++i)
      if(hash[i] != MAGIC_PREFIX[i])
         return false;

   Pipe pipe(new Base64_Decoder);
   pipe.start_msg();
   pipe.write(hash.c_str() + MAGIC_PREFIX.size());
   pipe.end_msg();

   SecureVector<byte> bin = pipe.read_all();

   if(bin.size() != BINARY_LENGTH)
      return false;

   byte alg_id = bin[0];

   u32bit kdf_iterations =
      WORK_FACTOR_SCALE * load_be<u16bit>(bin + ALGID_BYTES, 0);

   if(kdf_iterations == 0)
      return false;

   MessageAuthenticationCode* pbkdf_prf = get_pbkdf_prf(alg_id);

   if(pbkdf_prf == 0)
      return false; // unknown algorithm, reject

   PKCS5_PBKDF2 kdf(pbkdf_prf); // takes ownership of pointer

   SecureVector<byte> cmp = kdf.derive_key(
      PBKDF_OUTPUT_LEN, pass,
      &bin[ALGID_BYTES + WORKFACTOR_BYTES], SALT_BYTES,
      kdf_iterations).bits_of();

   return same_mem(cmp.begin(),
                   bin.begin() + ALGID_BYTES + WORKFACTOR_BYTES + SALT_BYTES,
                   PBKDF_OUTPUT_LEN);
   }

}
