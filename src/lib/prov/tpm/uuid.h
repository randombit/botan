/*
* UUID type
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UUID_H__
#define BOTAN_UUID_H__

#include <botan/secmem.h>
#include <botan/hex.h>
#include <sstream>

namespace Botan {

// TODO: move to util?
class UUID
   {
   public:
      // Represents an unassigned UUID object
      UUID() : m_uuid(0) {}

      UUID(RandomNumberGenerator& rng)
         {
         m_uuid.resize(16);
         rng.randomize(m_uuid.data(), m_uuid.size());

         // Mark as a random UUID (RFC 4122 sec 4.4)
         m_uuid[6] = 0x40 | (m_uuid[6] & 0x0F);

         // Set two reserved bits
         m_uuid[8] = 0xC0 | (m_uuid[8] & 0x3F);
         }

      UUID(const std::vector<uint8_t>& blob)
         {
         if(blob.size() != 16)
            {
            throw Invalid_Argument("Bad UUID blob " + hex_encode(blob));
            }

         m_uuid = blob;
         }

      UUID(const std::string& uuid_str)
         {
         if(uuid_str.size() != 36 ||
            uuid_str[8] != '-' ||
            uuid_str[14] != '-' ||
            uuid_str[19] != '-' ||
            uuid_str[24] != '-')
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


      std::string to_string() const
         {
         std::string h = hex_encode(m_uuid);

         h.insert(8, "-");
         h.insert(14, "-");
         h.insert(19, "-");
         h.insert(24, "-");

         return h;
         }

      const std::vector<uint8_t> binary_value() const { return m_uuid; }

      bool operator==(const UUID& other)
         {
         return m_uuid == other.m_uuid;
         }

      bool operator!=(const UUID& other) { return !(*this == other); }

      bool is_valid() const { return m_uuid.size() == 16; }

   private:
      std::vector<uint8_t> m_uuid;
   };

}

#endif
