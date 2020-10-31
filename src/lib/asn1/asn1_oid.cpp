/*
* ASN.1 OID
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_obj.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/internal/bit_ops.h>
#include <botan/parsing.h>
#include <botan/oids.h>
#include <algorithm>
#include <sstream>

namespace Botan {

namespace {

// returns empty on invalid
std::vector<uint32_t> parse_oid_str(const std::string& oid)
   {
   try
      {
      std::string elem;
      std::vector<uint32_t> oid_elems;

      for(char c : oid)
         {
         if(c == '.')
            {
            if(elem.empty())
               return std::vector<uint32_t>();
            oid_elems.push_back(to_u32bit(elem));
            elem.clear();
            }
         else
            {
            elem += c;
            }
         }

      if(elem.empty())
         return std::vector<uint32_t>();
      oid_elems.push_back(to_u32bit(elem));

      if(oid_elems.size() < 2)
         return std::vector<uint32_t>();

      return oid_elems;
      }
   catch(Invalid_Argument&) // thrown by to_u32bit
      {
      return std::vector<uint32_t>();
      }
   }

}

//static
OID OID::from_string(const std::string& str)
   {
   if(str.empty())
      throw Invalid_Argument("OID::from_string argument must be non-empty");

   const OID o = OIDS::str2oid_or_empty(str);
   if(o.has_value())
      return o;

   std::vector<uint32_t> raw = parse_oid_str(str);

   if(raw.size() > 0)
      return OID(std::move(raw));

   throw Lookup_Error("No OID associated with name " + str);
   }

/*
* ASN.1 OID Constructor
*/
OID::OID(const std::string& oid_str)
   {
   if(!oid_str.empty())
      {
      m_id = parse_oid_str(oid_str);

      if(m_id.size() < 2 || m_id[0] > 2)
         throw Invalid_OID(oid_str);
      if((m_id[0] == 0 || m_id[0] == 1) && m_id[1] > 39)
         throw Invalid_OID(oid_str);
      }
   }

/*
* Return this OID as a string
*/
std::string OID::to_string() const
   {
   std::ostringstream oss;
   for(size_t i = 0; i != m_id.size(); ++i)
      {
      oss << m_id[i];
      if(i != m_id.size() - 1)
         oss << ".";
      }
   return oss.str();
   }

std::string OID::to_formatted_string() const
   {
   const std::string s = OIDS::oid2str_or_empty(*this);
   if(!s.empty())
      return s;
   return this->to_string();
   }

/*
* Append another component to the OID
*/
OID operator+(const OID& oid, uint32_t new_component)
   {
   std::vector<uint32_t> val = oid.get_components();
   val.push_back(new_component);
   return OID(std::move(val));
   }

/*
* Compare two OIDs
*/
bool operator<(const OID& a, const OID& b)
   {
   const std::vector<uint32_t>& oid1 = a.get_components();
   const std::vector<uint32_t>& oid2 = b.get_components();

   return std::lexicographical_compare(oid1.begin(), oid1.end(),
                                       oid2.begin(), oid2.end());
   }

/*
* DER encode an OBJECT IDENTIFIER
*/
void OID::encode_into(DER_Encoder& der) const
   {
   if(m_id.size() < 2)
      throw Invalid_Argument("OID::encode_into: OID is invalid");

   std::vector<uint8_t> encoding;

   if(m_id[0] > 2 || m_id[1] >= 40)
      throw Encoding_Error("Invalid OID prefix, cannot encode");

   encoding.push_back(static_cast<uint8_t>(40 * m_id[0] + m_id[1]));

   for(size_t i = 2; i != m_id.size(); ++i)
      {
      if(m_id[i] == 0)
         encoding.push_back(0);
      else
         {
         size_t blocks = high_bit(m_id[i]) + 6;
         blocks = (blocks - (blocks % 7)) / 7;

         BOTAN_ASSERT(blocks > 0, "Math works");

         for(size_t j = 0; j != blocks - 1; ++j)
            encoding.push_back(0x80 | ((m_id[i] >> 7*(blocks-j-1)) & 0x7F));
         encoding.push_back(m_id[i] & 0x7F);
         }
      }
   der.add_object(OBJECT_ID, UNIVERSAL, encoding);
   }

/*
* Decode a BER encoded OBJECT IDENTIFIER
*/
void OID::decode_from(BER_Decoder& decoder)
   {
   BER_Object obj = decoder.get_next_object();
   if(obj.tagging() != OBJECT_ID)
      throw BER_Bad_Tag("Error decoding OID, unknown tag", obj.tagging());

   const size_t length = obj.length();
   const uint8_t* bits = obj.bits();

   if(length < 2 && !(length == 1 && bits[0] == 0))
      {
      throw BER_Decoding_Error("OID encoding is too short");
      }

   m_id.clear();
   m_id.push_back(bits[0] / 40);
   m_id.push_back(bits[0] % 40);

   size_t i = 0;
   while(i != length - 1)
      {
      uint32_t component = 0;
      while(i != length - 1)
         {
         ++i;

         if(component >> (32-7))
            throw Decoding_Error("OID component overflow");

         component = (component << 7) + (bits[i] & 0x7F);

         if(!(bits[i] & 0x80))
            break;
         }
      m_id.push_back(component);
      }
   }

}
