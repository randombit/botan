/**
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/argon2.h>
#include <botan/rng.h>
#include <botan/base64.h>
#include <botan/parsing.h>
#include <sstream>

namespace Botan {

namespace {

std::string strip_padding(std::string s)
   {
   while(s.size() > 0 && s[s.size()-1] == '=')
      s.resize(s.size() - 1);
   return s;
   }

}

std::string argon2_generate_pwhash(const char* password, size_t password_len,
                                   RandomNumberGenerator& rng,
                                   size_t p, size_t M, size_t t,
                                   uint8_t y, size_t salt_len, size_t output_len)
   {
   std::vector<uint8_t> salt(salt_len);
   rng.randomize(salt.data(), salt.size());

   std::vector<uint8_t> output(output_len);
   argon2(output.data(), output.size(),
          password, password_len,
          salt.data(), salt.size(),
          nullptr, 0,
          nullptr, 0,
          y, p, M, t);

   std::ostringstream oss;

   if(y == 0)
      oss << "$argon2d$";
   else if(y == 1)
      oss << "$argon2i$";
   else
      oss << "$argon2id$";

   oss << "v=19$m=" << M << ",t=" << t << ",p=" << p << "$";
   oss << strip_padding(base64_encode(salt)) << "$" << strip_padding(base64_encode(output));

   return oss.str();
   }

bool argon2_check_pwhash(const char* password, size_t password_len,
                         const std::string& input_hash)
   {
   const std::vector<std::string> parts = split_on(input_hash, '$');

   if(parts.size() != 5)
      return false;

   uint8_t family = 0;

   if(parts[0] == "argon2d")
      family = 0;
   else if(parts[0] == "argon2i")
      family = 1;
   else if(parts[0] == "argon2id")
      family = 2;
   else
      return false;

   if(parts[1] != "v=19")
      return false;

   const std::vector<std::string> params = split_on(parts[2], ',');

   if(params.size() != 3)
      return false;

   size_t M = 0, t = 0, p = 0;

   for(auto param_str : params)
      {
      const std::vector<std::string> param = split_on(param_str, '=');

      if(param.size() != 2)
         return false;

      const std::string key = param[0];
      const size_t val = to_u32bit(param[1]);
      if(key == "m")
         M = val;
      else if(key == "t")
         t = val;
      else if(key == "p")
         p = val;
      else
         return false;
      }

   std::vector<uint8_t> salt(base64_decode_max_output(parts[3].size()));
   salt.resize(base64_decode(salt.data(), parts[3], false));

   std::vector<uint8_t> hash(base64_decode_max_output(parts[4].size()));
   hash.resize(base64_decode(hash.data(), parts[4], false));

   if(hash.size() < 4)
      return false;

   std::vector<uint8_t> generated(hash.size());
   argon2(generated.data(), generated.size(),
          password, password_len,
          salt.data(), salt.size(),
          nullptr, 0,
          nullptr, 0,
          family, p, M, t);

   return constant_time_compare(generated.data(), hash.data(), generated.size());
   }

}
