/*
* UUID type
* (C) 2015,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/uuid.h>
#include <botan/rng.h>
#include <botan/hex.h>
#include <sstream>

namespace Botan {

UUID::UUID(RandomNumberGenerator& rng)
   {
   m_uuid.resize(16);
   rng.randomize(m_uuid.data(), m_uuid.size());

   // Mark as a random v4 UUID (RFC 4122 sec 4.4)
   m_uuid[6] = 0x40 | (m_uuid[6] & 0x0F);

   // Set reserved bits
   m_uuid[8] = 0x80 | (m_uuid[8] & 0x3F);
   }

UUID::UUID(const std::vector<uint8_t>& blob)
   {
   if(blob.size() != 16)
      {
      throw Invalid_Argument("Bad UUID blob " + hex_encode(blob));
      }

   m_uuid = blob;
   }

UUID::UUID(const std::string& uuid_str)
   {
   if(uuid_str.size() != 36 ||
      uuid_str[8] != '-' ||
      uuid_str[13] != '-' ||
      uuid_str[18] != '-' ||
      uuid_str[23] != '-')
      {
      throw Invalid_Argument("Bad UUID '" + uuid_str + "'");
      }

   std::string just_hex;
   for(size_t i = 0; i != uuid_str.size(); ++i)
      {
      char c = uuid_str[i];

      if(c == '-')
         continue;

      just_hex += c;
      }

   m_uuid = hex_decode(just_hex);

   if(m_uuid.size() != 16)
      {
      throw Invalid_Argument("Bad UUID '" + uuid_str + "'");
      }
   }

std::string UUID::to_string() const
   {
   if(is_valid() == false)
      throw Invalid_State("UUID object is empty cannot convert to string");

   std::string h = hex_encode(m_uuid);

   h.insert(8, "-");
   h.insert(13, "-");
   h.insert(18, "-");
   h.insert(23, "-");

   return h;
   }

}
