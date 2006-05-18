/*************************************************
* BER Decoding Source File                       *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/ber_dec.h>
#include <botan/asn1_int.h>
#include <botan/parsing.h>
#include <botan/bigint.h>

#include <assert.h>

namespace Botan {

namespace {

/*************************************************
* Check an object's type and size                *
*************************************************/
void check_object(const BER_Object& obj,
                  ASN1_Tag type_tag, ASN1_Tag class_tag,
                  u32bit length = 0, bool check_length = false)
   {
   if(obj.type_tag != type_tag || obj.class_tag != class_tag)
      throw BER_Decoding_Error("Tag mismatch when decoding");
   if(check_length && obj.value.size() != length)
      throw BER_Decoding_Error("Incorrect size for type");
   }

}

/*************************************************
* Decode a BER encoded NULL                      *
*************************************************/
BER_Decoder& BER_Decoder::decode_null()
   {
   check_object(get_next_object(), NULL_TAG, UNIVERSAL, 0, true);
   return (*this);
   }

/*************************************************
* Decode a BER encoded BOOLEAN                   *
*************************************************/
BER_Decoder& BER_Decoder::decode(bool& out)
   {
   return decode(out, BOOLEAN, UNIVERSAL);
   }

/*************************************************
* Decode a small BER encoded INTEGER             *
*************************************************/
BER_Decoder& BER_Decoder::decode(u32bit& out)
   {
   return decode(out, INTEGER, UNIVERSAL);
   }

/*************************************************
* Decode a BER encoded INTEGER                   *
*************************************************/
BER_Decoder& BER_Decoder::decode(BigInt& out)
   {
   return decode(out, INTEGER, UNIVERSAL);
   }

/*************************************************
* Decode a BER encoded BOOLEAN                   *
*************************************************/
BER_Decoder& BER_Decoder::decode(bool& out,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   BER_Object obj = get_next_object();
   check_object(obj, type_tag, class_tag, 1, true);
   out = (obj.value[0]) ? true : false;
   return (*this);
   }

/*************************************************
* Decode a small BER encoded INTEGER             *
*************************************************/
BER_Decoder& BER_Decoder::decode(u32bit& out,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   BigInt integer;
   decode(integer, type_tag, class_tag);
   out = integer.to_u32bit();
   return (*this);
   }

/*************************************************
* Decode a BER encoded INTEGER                   *
*************************************************/
BER_Decoder& BER_Decoder::decode(BigInt& out,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   BER_Object obj = get_next_object();
   check_object(obj, type_tag, class_tag);

   if(obj.value.is_empty())
      out = 0;
   else
      {
      const bool negative = (obj.value[0] & 0x80) ? true : false;

      if(negative)
         {
         for(u32bit j = obj.value.size(); j > 0; --j)
            if(obj.value[j-1]--)
               break;
         for(u32bit j = 0; j != obj.value.size(); ++j)
            obj.value[j] = ~obj.value[j];
         }

      out = BigInt(obj.value, obj.value.size());

      if(negative)
         out.flip_sign();
      }

   return (*this);
   }

/*************************************************
* BER decode a BIT STRING or OCTET STRING        *
*************************************************/
BER_Decoder& BER_Decoder::decode(MemoryRegion<byte>& out, ASN1_Tag real_type)
   {
   return decode(out, real_type, real_type, UNIVERSAL);
   }

/*************************************************
* BER decode a BIT STRING or OCTET STRING        *
*************************************************/
BER_Decoder& BER_Decoder::decode(MemoryRegion<byte>& buffer,
                                 ASN1_Tag real_type,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   if(real_type != OCTET_STRING && real_type != BIT_STRING)
      throw BER_Bad_Tag("Bad tag for {BIT,OCTET} STRING", real_type);

   BER_Object obj = get_next_object();
   check_object(obj, type_tag, class_tag);

   if(real_type == OCTET_STRING)
      buffer = obj.value;
   else
      {
      if(obj.value[0] >= 8)
         throw BER_Decoding_Error("Bad number of unused bits in BIT STRING");
      buffer.set(obj.value + 1, obj.value.size() - 1);
      }
   return (*this);
   }

namespace BER {

/*************************************************
* Decode and return a BER encoded SEQUENCE       *
*************************************************/
BER_Decoder get_subsequence(BER_Decoder& decoder)
   {
   return get_subsequence(decoder, SEQUENCE, CONSTRUCTED);
   }

/*************************************************
* Decode and return a BER encoded SET            *
*************************************************/
BER_Decoder get_subset(BER_Decoder& decoder)
   {
   return get_subset(decoder, SET, CONSTRUCTED);
   }

/*************************************************
* Decode and return a BER encoded SEQUENCE       *
*************************************************/
BER_Decoder get_subsequence(BER_Decoder& decoder,
                            ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   BER_Object obj = decoder.get_next_object();
   check_object(obj, type_tag, ASN1_Tag(class_tag | CONSTRUCTED));
   return BER_Decoder(obj.value, obj.value.size());
   }

/*************************************************
* Decode and return a BER encoded SET            *
*************************************************/
BER_Decoder get_subset(BER_Decoder& decoder,
                       ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   BER_Object obj = decoder.get_next_object();
   check_object(obj, type_tag, ASN1_Tag(class_tag | CONSTRUCTED));
   return BER_Decoder(obj.value, obj.value.size());
   }

/*************************************************
* Convert a BER object into a string object      *
*************************************************/
std::string to_string(const BER_Object& obj)
   {
   std::string str((const char*)obj.value.begin(), obj.value.size());
   return str;
   }

/*************************************************
* Decode an OPTIONAL string type                 *
*************************************************/
bool decode_optional_string(BER_Decoder& in, MemoryRegion<byte>& out,
                            ASN1_Tag real_type,
                            ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   BER_Object obj = in.get_next_object();

   if(obj.type_tag == type_tag && obj.class_tag == class_tag)
      {
      if(class_tag & CONSTRUCTED)
         {
         BER_Decoder stored_value(obj.value);
         stored_value.decode(out, real_type);
         stored_value.verify_end();
         }
      else
         {
         in.push_back(obj);
         in.decode(out, real_type, type_tag, class_tag);
         }
      return true;
      }
   else
      {
      out.clear();
      in.push_back(obj);
      return false;
      }
   }

}

}
