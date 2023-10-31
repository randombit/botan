/**
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/argon2fmt.h>

#include <botan/base64.h>
#include <botan/mem_ops.h>
#include <botan/pwdhash.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>

namespace Botan {

namespace {

std::string strip_padding(std::string s) {
   while(!s.empty() && s[s.size() - 1] == '=') {
      s.resize(s.size() - 1);
   }
   return s;
}

std::string argon2_family(uint8_t y) {
   if(y == 0) {
      return "Argon2d";
   } else if(y == 1) {
      return "Argon2i";
   } else if(y == 2) {
      return "Argon2id";
   } else {
      throw Not_Implemented("Unknown Argon2 family type");
   }
}

}  // namespace

std::string argon2_generate_pwhash(const char* password,
                                   size_t password_len,
                                   RandomNumberGenerator& rng,
                                   size_t p,
                                   size_t M,
                                   size_t t,
                                   uint8_t y,
                                   size_t salt_len,
                                   size_t output_len) {
   std::vector<uint8_t> salt(salt_len);
   rng.randomize(salt.data(), salt.size());

   std::vector<uint8_t> output(output_len);

   auto pwdhash_fam = PasswordHashFamily::create_or_throw(argon2_family(y));
   auto pwdhash = pwdhash_fam->from_params(M, t, p);

   pwdhash->derive_key(output.data(), output.size(), password, password_len, salt.data(), salt.size());

   const auto enc_salt = strip_padding(base64_encode(salt));
   const auto enc_output = strip_padding(base64_encode(output));

   const std::string argon2_mode = [&]() -> std::string {
      if(y == 0) {
         return "d";
      } else if(y == 1) {
         return "i";
      } else {
         return "id";
      }
   }();

   return fmt("$argon2{}$v=19$m={},t={},p={}${}${}", argon2_mode, M, t, p, enc_salt, enc_output);
}

bool argon2_check_pwhash(const char* password, size_t password_len, std::string_view input_hash) {
   const std::vector<std::string> parts = split_on(input_hash, '$');

   if(parts.size() != 5) {
      return false;
   }

   uint8_t family = 0;

   if(parts[0] == "argon2d") {
      family = 0;
   } else if(parts[0] == "argon2i") {
      family = 1;
   } else if(parts[0] == "argon2id") {
      family = 2;
   } else {
      return false;
   }

   if(parts[1] != "v=19") {
      return false;
   }

   const std::vector<std::string> params = split_on(parts[2], ',');

   if(params.size() != 3) {
      return false;
   }

   size_t M = 0, t = 0, p = 0;

   for(const auto& param_str : params) {
      const std::vector<std::string> param = split_on(param_str, '=');

      if(param.size() != 2) {
         return false;
      }

      std::string_view key = param[0];
      const size_t val = to_u32bit(param[1]);
      if(key == "m") {
         M = val;
      } else if(key == "t") {
         t = val;
      } else if(key == "p") {
         p = val;
      } else {
         return false;
      }
   }

   std::vector<uint8_t> salt(base64_decode_max_output(parts[3].size()));
   salt.resize(base64_decode(salt.data(), parts[3], false));

   std::vector<uint8_t> hash(base64_decode_max_output(parts[4].size()));
   hash.resize(base64_decode(hash.data(), parts[4], false));

   if(hash.size() < 4) {
      return false;
   }

   std::vector<uint8_t> generated(hash.size());
   auto pwdhash_fam = PasswordHashFamily::create_or_throw(argon2_family(family));
   auto pwdhash = pwdhash_fam->from_params(M, t, p);

   pwdhash->derive_key(generated.data(), generated.size(), password, password_len, salt.data(), salt.size());

   return CT::is_equal(generated.data(), hash.data(), generated.size()).as_bool();
}

}  // namespace Botan
