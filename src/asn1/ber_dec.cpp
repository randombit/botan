/*
* BER Decoder
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/loadstor.h>

namespace Botan {

namespace {

/*
* BER decode an ASN.1 type tag
*/
u32bit decode_tag(DataSource* ber, ASN1_Tag& type_tag, ASN1_Tag& class_tag)
   {
   byte b;
   if(!ber->read_byte(b))
      {
      class_tag = type_tag = NO_OBJECT;
      return 0;
      }

   if((b & 0x1F) != 0x1F)
      {
      type_tag = ASN1_Tag(b & 0x1F);
      class_tag = ASN1_Tag(b & 0xE0);
      return 1;
      }

   u32bit tag_bytes = 1;
   class_tag = ASN1_Tag(b & 0xE0);

   u32bit tag_buf = 0;
   while(true)
      {
      if(!ber->read_byte(b))
         throw BER_Decoding_Error("Long-form tag truncated");
      if(tag_buf & 0xFF000000)
         throw BER_Decoding_Error("Long-form tag overflowed 32 bits");
      ++tag_bytes;
      tag_buf = (tag_buf << 7) | (b & 0x7F);
      if((b & 0x80) == 0) break;
      }
   type_tag = ASN1_Tag(tag_buf);
   return tag_bytes;
   }

/*
* Find the EOC marker
*/
u32bit find_eoc(DataSource*);

/*
* BER decode an ASN.1 length field
*/
u32bit decode_length(DataSource* ber, u32bit& field_size)
   {
   byte b;
   if(!ber->read_byte(b))
      throw BER_Decoding_Error("Length field not found");
   field_size = 1;
   if((b & 0x80) == 0)
      return b;

   field_size += (b & 0x7F);
   if(field_size == 1) return find_eoc(ber);
   if(field_size > 5)
      throw BER_Decoding_Error("Length field is too large");

   u32bit length = 0;

   for(u32bit j = 0; j != field_size - 1; ++j)
      {
      if(get_byte(0, length) != 0)
         throw BER_Decoding_Error("Field length overflow");
      if(!ber->read_byte(b))
         throw BER_Decoding_Error("Corrupted length field");
      length = (length << 8) | b;
      }
   return length;
   }

/*
* BER decode an ASN.1 length field
*/
u32bit decode_length(DataSource* ber)
   {
   u32bit dummy;
   return decode_length(ber, dummy);
   }

/*
* Find the EOC marker
*/
u32bit find_eoc(DataSource* ber)
   {
   SecureVector<byte> buffer(DEFAULT_BUFFERSIZE), data;

   while(true)
      {
      const u32bit got = ber->peek(buffer, buffer.size(), data.size());
      if(got == 0)
         break;
      data.append(buffer, got);
      }

   DataSource_Memory source(data);
   data.destroy();

   u32bit length = 0;
   while(true)
      {
      ASN1_Tag type_tag, class_tag;
      u32bit tag_size = decode_tag(&source, type_tag, class_tag);
      if(type_tag == NO_OBJECT)
         break;

      u32bit length_size = 0;
      u32bit item_size = decode_length(&source, length_size);
      source.discard_next(item_size);

      length += item_size + length_size + tag_size;

      if(type_tag == EOC)
         break;
      }
   return length;
   }

}

/*
* Check a type invariant on BER data
*/
void BER_Object::assert_is_a(ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   if(this->type_tag != type_tag || this->class_tag != class_tag)
      throw BER_Decoding_Error("Tag mismatch when decoding");
   }

/*
* Check if more objects are there
*/
bool BER_Decoder::more_items() const
   {
   if(source->end_of_data() && (pushed.type_tag == NO_OBJECT))
      return false;
   return true;
   }

/*
* Verify that no bytes remain in the source
*/
BER_Decoder& BER_Decoder::verify_end()
   {
   if(!source->end_of_data() || (pushed.type_tag != NO_OBJECT))
      throw Invalid_State("BER_Decoder::verify_end called, but data remains");
   return (*this);
   }

/*
* Save all the bytes remaining in the source
*/
BER_Decoder& BER_Decoder::raw_bytes(MemoryRegion<byte>& out)
   {
   out.destroy();
   byte buf;
   while(source->read_byte(buf))
      out.append(buf);
   return (*this);
   }

/*
* Discard all the bytes remaining in the source
*/
BER_Decoder& BER_Decoder::discard_remaining()
   {
   byte buf;
   while(source->read_byte(buf))
      ;
   return (*this);
   }

/*
* Return the BER encoding of the next object
*/
BER_Object BER_Decoder::get_next_object()
   {
   BER_Object next;

   if(pushed.type_tag != NO_OBJECT)
      {
      next = pushed;
      pushed.class_tag = pushed.type_tag = NO_OBJECT;
      return next;
      }

   decode_tag(source, next.type_tag, next.class_tag);
   if(next.type_tag == NO_OBJECT)
      return next;

   u32bit length = decode_length(source);
   next.value.create(length);
   if(source->read(next.value, length) != length)
      throw BER_Decoding_Error("Value truncated");

   if(next.type_tag == EOC && next.class_tag == UNIVERSAL)
      return get_next_object();

   return next;
   }

/*
* Push a object back into the stream
*/
void BER_Decoder::push_back(const BER_Object& obj)
   {
   if(pushed.type_tag != NO_OBJECT)
      throw Invalid_State("BER_Decoder: Only one push back is allowed");
   pushed = obj;
   }

/*
* Begin decoding a CONSTRUCTED type
*/
BER_Decoder BER_Decoder::start_cons(ASN1_Tag type_tag,
                                    ASN1_Tag class_tag)
   {
   BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, ASN1_Tag(class_tag | CONSTRUCTED));

   BER_Decoder result(obj.value, obj.value.size());
   result.parent = this;
   return result;
   }

/*
* Finish decoding a CONSTRUCTED type
*/
BER_Decoder& BER_Decoder::end_cons()
   {
   if(!parent)
      throw Invalid_State("BER_Decoder::end_cons called with NULL parent");
   if(!source->end_of_data())
      throw Decoding_Error("BER_Decoder::end_cons called with data left");
   return (*parent);
   }

/*
* BER_Decoder Constructor
*/
BER_Decoder::BER_Decoder(DataSource& src)
   {
   source = &src;
   owns = false;
   pushed.type_tag = pushed.class_tag = NO_OBJECT;
   parent = 0;
   }

/*
* BER_Decoder Constructor
 */
BER_Decoder::BER_Decoder(const byte data[], u32bit length)
   {
   source = new DataSource_Memory(data, length);
   owns = true;
   pushed.type_tag = pushed.class_tag = NO_OBJECT;
   parent = 0;
   }

/*
* BER_Decoder Constructor
*/
BER_Decoder::BER_Decoder(const MemoryRegion<byte>& data)
   {
   source = new DataSource_Memory(data);
   owns = true;
   pushed.type_tag = pushed.class_tag = NO_OBJECT;
   parent = 0;
   }

/*
* BER_Decoder Copy Constructor
*/
BER_Decoder::BER_Decoder(const BER_Decoder& other)
   {
   source = other.source;
   owns = false;
   if(other.owns)
      {
      other.owns = false;
      owns = true;
      }
   pushed.type_tag = pushed.class_tag = NO_OBJECT;
   parent = other.parent;
   }

/*
* BER_Decoder Destructor
*/
BER_Decoder::~BER_Decoder()
   {
   if(owns)
      delete source;
   source = 0;
   }

/*
* Request for an object to decode itself
*/
BER_Decoder& BER_Decoder::decode(ASN1_Object& obj)
   {
   obj.decode_from(*this);
   return (*this);
   }

/*
* Decode a BER encoded NULL
*/
BER_Decoder& BER_Decoder::decode_null()
   {
   BER_Object obj = get_next_object();
   obj.assert_is_a(NULL_TAG, UNIVERSAL);
   if(obj.value.size())
      throw BER_Decoding_Error("NULL object had nonzero size");
   return (*this);
   }

/*
* Decode a BER encoded BOOLEAN
*/
BER_Decoder& BER_Decoder::decode(bool& out)
   {
   return decode(out, BOOLEAN, UNIVERSAL);
   }

/*
* Decode a small BER encoded INTEGER
*/
BER_Decoder& BER_Decoder::decode(u32bit& out)
   {
   return decode(out, INTEGER, UNIVERSAL);
   }

/*
* Decode a BER encoded INTEGER
*/
BER_Decoder& BER_Decoder::decode(BigInt& out)
   {
   return decode(out, INTEGER, UNIVERSAL);
   }

/*
* Decode a BER encoded BOOLEAN
*/
BER_Decoder& BER_Decoder::decode(bool& out,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, class_tag);

   if(obj.value.size() != 1)
      throw BER_Decoding_Error("BER boolean value had invalid size");

   out = (obj.value[0]) ? true : false;
   return (*this);
   }

/*
* Decode a small BER encoded INTEGER
*/
BER_Decoder& BER_Decoder::decode(u32bit& out,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   BigInt integer;
   decode(integer, type_tag, class_tag);
   out = integer.to_u32bit();
   return (*this);
   }

/*
* Decode a BER encoded INTEGER
*/
BER_Decoder& BER_Decoder::decode(BigInt& out,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, class_tag);

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

/*
* BER decode a BIT STRING or OCTET STRING
*/
BER_Decoder& BER_Decoder::decode(MemoryRegion<byte>& out, ASN1_Tag real_type)
   {
   return decode(out, real_type, real_type, UNIVERSAL);
   }

/*
* BER decode a BIT STRING or OCTET STRING
*/
BER_Decoder& BER_Decoder::decode(MemoryRegion<byte>& buffer,
                                 ASN1_Tag real_type,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   if(real_type != OCTET_STRING && real_type != BIT_STRING)
      throw BER_Bad_Tag("Bad tag for {BIT,OCTET} STRING", real_type);

   BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, class_tag);

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

/*
* Decode an OPTIONAL string type
*/
BER_Decoder& BER_Decoder::decode_optional_string(MemoryRegion<byte>& out,
                                                 ASN1_Tag real_type,
                                                 u16bit type_no)
   {
   BER_Object obj = get_next_object();

   ASN1_Tag type_tag = static_cast<ASN1_Tag>(type_no);

   out.clear();
   push_back(obj);

   if(obj.type_tag == type_tag && obj.class_tag == CONTEXT_SPECIFIC)
      decode(out, real_type, type_tag, CONTEXT_SPECIFIC);

   return (*this);
   }

}
