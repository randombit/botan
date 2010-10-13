/*
* ASN.1 OID
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/asn1_oid.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/internal/bit_ops.h>
#include <botan/parsing.h>

namespace Botan {

/*
* ASN.1 OID Constructor
*/
OID::OID(const std::string& oid_str)
   {
   if(oid_str != "")
      {
      try
         {
         id = parse_asn1_oid(oid_str);
         }
      catch(...)
         {
         throw Invalid_OID(oid_str);
         }

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
   for(size_t i = 0; i != id.size(); ++i)
      {
      oid_str += to_string(id[i]);
      if(i != id.size() - 1)
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
   for(size_t i = 0; i != id.size(); ++i)
      if(id[i] != oid.id[i])
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
   for(size_t i = 0; i != oid1.size(); ++i)
      {
      if(oid1[i] < oid2[i])
         return true;
      if(oid1[i] > oid2[i])
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
   encoding.push_back(40 * id[0] + id[1]);

   for(size_t i = 2; i != id.size(); ++i)
      {
      if(id[i] == 0)
         encoding.push_back(0);
      else
         {
         size_t blocks = high_bit(id[i]) + 6;
         blocks = (blocks - (blocks % 7)) / 7;

         for(size_t j = 0; j != blocks - 1; ++j)
            encoding.push_back(0x80 | ((id[i] >> 7*(blocks-j-1)) & 0x7F));
         encoding.push_back(id[i] & 0x7F);
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

   size_t i = 0;
   while(i != obj.value.size() - 1)
      {
      u32bit component = 0;
      while(i != obj.value.size() - 1)
         {
         ++i;
         component = (component << 7) + (obj.value[i] & 0x7F);
         if(!(obj.value[i] & 0x80))
            break;
         }
      id.push_back(component);
      }
   }

}
