/*
* Cipher Modes
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cipher_mode.h>
#include <sstream>

namespace Botan {

Cipher_Mode* get_cipher_mode(const std::string& algo_spec, Cipher_Dir direction)
   {
   const char* dir_string = (direction == ENCRYPTION) ? "_Encryption" : "_Decryption";

   const std::string provider = "";

   std::unique_ptr<Transform> t;

   t.reset(get_transform(algo_spec, provider, dir_string));

   if(Cipher_Mode* cipher = dynamic_cast<Cipher_Mode*>(t.get()))
      {
      t.release();
      return cipher;
      }

   const std::vector<std::string> algo_parts = split_on(algo_spec, '/');
   if(algo_parts.size() < 2)
      return nullptr;

   const std::string cipher_name = algo_parts[0];
   const std::vector<std::string> mode_info = parse_algorithm_name(algo_parts[1]);

   if(mode_info.empty())
      return nullptr;

   std::ostringstream t_name;

   t_name << mode_info[0] << dir_string << '(' << cipher_name;
   for(size_t i = 1; i < mode_info.size(); ++i)
      t_name << ',' << mode_info[i];
   for(size_t i = 2; i < algo_parts.size(); ++i)
      t_name << ',' << algo_parts[i];
   t_name << ')';

   t.reset(get_transform(t_name.str(), provider));

   if(Cipher_Mode* cipher = dynamic_cast<Cipher_Mode*>(t.get()))
      {
      t.release();
      return cipher;
      }

   return nullptr;
   }

}
