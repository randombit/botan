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

   try {
      // Validate input format before manuel parsing
      static_cast<void>(split_on(kv, ','));
   } catch(std::exception&) {
      throw Invalid_Argument("Bad KV spec");
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
            throw Invalid_Argument("Bad KV spec empty key");
         }

         if(m.contains(cur_key)) {
            throw Invalid_Argument("Bad KV spec duplicated key");
         }
         m[cur_key] = cur_val;
         cur_key = "";
         cur_val = "";
         reading_key = true;
      } else if(c == '=' && !escaped) {
         if(!reading_key) {
            throw Invalid_Argument("Bad KV spec unexpected equals sign");
         }
         reading_key = false;
      } else {
         if(reading_key) {
            cur_key += c;
         } else {
            cur_val += c;
         }
         escaped = false;
      }
   }

   if(!cur_key.empty()) {
      if(!reading_key) {
         if(m.contains(cur_key)) {
            throw Invalid_Argument("Bad KV spec duplicated key");
         }
         m[cur_key] = cur_val;
      } else {
         throw Invalid_Argument("Bad KV spec incomplete string");
      }
   }

   return m;
}

}  // namespace Botan
