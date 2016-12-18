/*
* SRP-6a File Handling
* (C) 2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/srp6_files.h>
#include <botan/parsing.h>
#include <botan/base64.h>

namespace Botan {

SRP6_Authenticator_File::SRP6_Authenticator_File(std::istream& in)
   {
   if(!in)
      return; // no entries

   while(in.good())
      {
      std::string line;
      std::getline(in, line);

      std::vector<std::string> parts = split_on(line, ':');

      if(parts.size() != 4)
         throw Decoding_Error("Invalid line in SRP authenticator file");

      std::string username = parts[0];
      BigInt v = BigInt::decode(base64_decode(parts[1]));
      std::vector<uint8_t> salt = unlock(base64_decode(parts[2]));
      BigInt group_id_idx = BigInt::decode(base64_decode(parts[3]));

      std::string group_id;

      if(group_id_idx == 1)
         group_id = "modp/srp/1024";
      else if(group_id_idx == 2)
         group_id = "modp/srp/1536";
      else if(group_id_idx == 3)
         group_id = "modp/srp/2048";
      else
         continue; // unknown group, ignored

      m_entries[username] = SRP6_Data(v, salt, group_id);
      }
   }

bool SRP6_Authenticator_File::lookup_user(const std::string& username,
                                          BigInt& v,
                                          std::vector<uint8_t>& salt,
                                          std::string& group_id) const
   {
   std::map<std::string, SRP6_Data>::const_iterator i = m_entries.find(username);

   if(i == m_entries.end())
      return false;

   v = i->second.v;
   salt = i->second.salt;
   group_id = i->second.group_id;

   return true;
   }

}
