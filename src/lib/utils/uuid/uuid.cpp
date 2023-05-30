/*
* UUID type
* (C) 2015,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/uuid.h>

#include <botan/hex.h>
#include <botan/rng.h>
#include <botan/internal/fmt.h>
#include <sstream>

namespace Botan {

UUID::UUID(RandomNumberGenerator& rng) {
   m_uuid.resize(16);
   rng.randomize(m_uuid.data(), m_uuid.size());

   // Mark as a random v4 UUID (RFC 4122 sec 4.4)
   m_uuid[6] = 0x40 | (m_uuid[6] & 0x0F);

   // Set reserved bits
   m_uuid[8] = 0x80 | (m_uuid[8] & 0x3F);
}

UUID::UUID(const std::vector<uint8_t>& blob) {
   if(blob.size() != 16) {
      throw Invalid_Argument("Bad UUID blob " + hex_encode(blob));
   }

   m_uuid = blob;
}

UUID::UUID(std::string_view uuid_str) {
   if(uuid_str.size() != 36 || uuid_str[8] != '-' || uuid_str[13] != '-' || uuid_str[18] != '-' ||
      uuid_str[23] != '-') {
      throw Invalid_Argument(fmt("Bad UUID '{}'", uuid_str));
   }

   std::string just_hex;
   for(char c : uuid_str) {
      if(c == '-') {
         continue;
      }

      just_hex += c;
   }

   m_uuid = hex_decode(just_hex);

   if(m_uuid.size() != 16) {
      throw Invalid_Argument(fmt("Bad UUID '{}'", uuid_str));
   }
}

std::string UUID::to_string() const {
   if(is_valid() == false) {
      throw Invalid_State("UUID object is empty cannot convert to string");
   }

   const std::string raw = hex_encode(m_uuid);

   std::ostringstream formatted;

   for(size_t i = 0; i != raw.size(); ++i) {
      if(i == 8 || i == 12 || i == 16 || i == 20) {
         formatted << "-";
      }
      formatted << raw[i];
   }

   return formatted.str();
}

}  // namespace Botan
