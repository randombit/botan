/*
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/parsing.h>

#include <botan/exceptn.h>

namespace Botan {

std::map<std::string, std::string> read_kv(std::string_view kv) {
   std::map<std::string, std::string> m;
   if(kv.empty()) {
      return m;
   }

   std::vector<std::string> parts;

   try {
      parts = split_on(kv, ',');
   } catch(std::exception&) {
      throw_invalid_argument("Bad KV spec", __func__, __FILE__);
   }

   bool escaped = false;
   bool reading_key = true;
   std::string cur_key;
   std::string cur_val;

   for(char c : kv) {
      if(c == '\\' && !escaped) {
         escaped = true;
      } else if(c == ',' && !escaped) {
         if(cur_key.empty()) {
            throw_invalid_argument("Bad KV spec empty key", __func__, __FILE__);
         }

         if(m.find(cur_key) != m.end()) {
            throw_invalid_argument("Bad KV spec duplicated key", __func__, __FILE__);
         }
         m[cur_key] = cur_val;
         cur_key = "";
         cur_val = "";
         reading_key = true;
      } else if(c == '=' && !escaped) {
         if(reading_key == false) {
            throw_invalid_argument("Bad KV spec unexpected equals sign", __func__, __FILE__);
         }
         reading_key = false;
      } else {
         if(reading_key) {
            cur_key += c;
         } else {
            cur_val += c;
         }

         if(escaped) {
            escaped = false;
         }
      }
   }

   if(!cur_key.empty()) {
      if(reading_key == false) {
         if(m.find(cur_key) != m.end()) {
            throw_invalid_argument("Bad KV spec duplicated key", __func__, __FILE__);
         }
         m[cur_key] = cur_val;
      } else {
         throw_invalid_argument("Bad KV spec incomplete string", __func__, __FILE__);
      }
   }

   return m;
}

}  // namespace Botan
