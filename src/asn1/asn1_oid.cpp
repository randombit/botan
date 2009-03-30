/*
* ASN.1 OID
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/asn1_oid.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/bit_ops.h>
#include <botan/parsing.h>

namespace Botan {

/*
* ASN.1 OID Constructor
*/
OID::OID(const std::string& oid_str)
   {
   if(oid_str != "")
      {
      id = parse_asn1_oid(oid_str);
      if(id.size() < 2 || id[0] > 2)
         throw Invalid_OID(oid_str);
      if((id[0] == 0 || id[0] == 1) && id[1] > 39)
         throw Invalid_OID(oid_str);
      }
   }

/*
* Clear the current OID
*/
void OID::clear()
   {
   id.clear();
   }

/*
* Return this OID as a string
*/
std::string OID::as_string() const
   {
   std::string oid_str;
   for(u32bit j = 0; j != id.size(); ++j)
      {
      oid_str += to_string(id[j]);
      if(j != id.size() - 1)
         oid_str += '.';
      }
   return oid_str;
   }

/*
* OID equality comparison
*/
bool OID::operator==(const OID& oid) const
   {
   if(id.size() != oid.id.size())
      return false;
   for(u32bit j = 0; j != id.size(); ++j)
      if(id[j] != oid.id[j])
         return false;
   return true;
   }

/*
* Append another component to the OID
*/
OID& OID::operator+=(u32bit component)
   {
   id.push_back(component);
   return (*this);
   }

/*
* Append another component to the OID
*/
OID operator+(const OID& oid, u32bit component)
   {
   OID new_oid(oid);
   new_oid += component;
   return new_oid;
   }

/*
* OID inequality comparison
*/
bool operator!=(const OID& a, const OID& b)
   {
   return !(a == b);
   }

/*
* Compare two OIDs
*/
bool operator<(const OID& a, const OID& b)
   {
   std::vector<u32bit> oid1 = a.get_id();
   std::vector<u32bit> oid2 = b.get_id();

   if(oid1.size() < oid2.size())
      return true;
   if(oid1.size() > oid2.size())
      return false;
   for(u32bit j = 0; j != oid1.size(); ++j)
      {
      if(oid1[j] < oid2[j])
         return true;
      if(oid1[j] > oid2[j])
         return false;
      }
   return false;
   }

/*
* DER encode an OBJECT IDENTIFIER
*/
void OID::encode_into(DER_Encoder& der) const
   {
   if(id.size() < 2)
      throw Invalid_Argument("OID::encode_into: OID is invalid");

   MemoryVector<byte> encoding;
   encoding.append(40 * id[0] + id[1]);

   for(u32bit j = 2; j != id.size(); ++j)
      {
      if(id[j] == 0)
         encoding.append(0);
      else
         {
         u32bit blocks = high_bit(id[j]) + 6;
         blocks = (blocks - (blocks % 7)) / 7;

         for(u32bit k = 0; k != blocks - 1; ++k)
            encoding.append(0x80 | ((id[j] >> 7*(blocks-k-1)) & 0x7F));
         encoding.append(id[j] & 0x7F);
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
   if(obj.type_tag != OBJECT_ID || obj.class_tag != UNIVERSAL)
      throw BER_Bad_Tag("Error decoding OID, unknown tag",
                        obj.type_tag, obj.class_tag);
   if(obj.value.size() < 2)
      throw BER_Decoding_Error("OID encoding is too short");


   clear();
   id.push_back(obj.value[0] / 40);
   id.push_back(obj.value[0] % 40);

   u32bit j = 0;
   while(j != obj.value.size() - 1)
      {
      u32bit component = 0;
      while(j != obj.value.size() - 1)
         {
         ++j;
         component = (component << 7) + (obj.value[j] & 0x7F);
         if(!(obj.value[j] & 0x80))
            break;
         }
      id.push_back(component);
      }
   }

}
