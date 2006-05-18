/*************************************************
* BER Decoder Source File                        *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/ber_dec.h>
#include <botan/asn1_int.h>
#include <botan/bit_ops.h>

namespace Botan {

namespace {

/*************************************************
* BER decode an ASN.1 type tag                   *
*************************************************/
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

/*************************************************
* Find the EOC marker                            *
*************************************************/
u32bit find_eoc(DataSource*);

/*************************************************
* BER decode an ASN.1 length field               *
*************************************************/
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

/*************************************************
* BER decode an ASN.1 length field               *
*************************************************/
u32bit decode_length(DataSource* ber)
   {
   u32bit dummy;
   return decode_length(ber, dummy);
   }

/*************************************************
* Find the EOC marker                            *
*************************************************/
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

/*************************************************
* Check if more objects are there                *
*************************************************/
bool BER_Decoder::more_items() const
   {
   if(source->end_of_data() && (pushed.type_tag == NO_OBJECT))
      return false;
   return true;
   }

/*************************************************
* Verify that no bytes remain in the source      *
*************************************************/
void BER_Decoder::verify_end() const
   {
   if(!source->end_of_data() || (pushed.type_tag != NO_OBJECT))
      throw Invalid_State("BER_Decoder::verify_end called, but data remains");
   }

/*************************************************
* Return all the bytes remaining in the source   *
*************************************************/
SecureVector<byte> BER_Decoder::get_remaining()
   {
   SecureVector<byte> out;
   byte buf;
   while(source->read_byte(buf))
      out.append(buf);
   return out;
   }

/*************************************************
* Discard all the bytes remaining in the source  *
*************************************************/
void BER_Decoder::discard_remaining()
   {
   byte buf;
   while(source->read_byte(buf))
      ;
   }

/*************************************************
* Return the BER encoding of the next object     *
*************************************************/
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

/*************************************************
* Push a object back into the stream             *
*************************************************/
void BER_Decoder::push_back(const BER_Object& obj)
   {
   if(pushed.type_tag != NO_OBJECT)
      throw Invalid_State("BER_Decoder: Only one push back is allowed");
   pushed = obj;
   }

/*************************************************
* BER_Decoder Constructor                        *
*************************************************/
BER_Decoder::BER_Decoder(DataSource& src)
   {
   source = &src;
   owns = false;
   pushed.type_tag = pushed.class_tag = NO_OBJECT;
   }

/*************************************************
* BER_Decoder Constructor                        *
 *************************************************/
BER_Decoder::BER_Decoder(const byte data[], u32bit length)
   {
   source = new DataSource_Memory(data, length);
   owns = true;
   pushed.type_tag = pushed.class_tag = NO_OBJECT;
   }

/*************************************************
* BER_Decoder Constructor                        *
*************************************************/
BER_Decoder::BER_Decoder(const MemoryRegion<byte>& data)
   {
   source = new DataSource_Memory(data);
   owns = true;
   pushed.type_tag = pushed.class_tag = NO_OBJECT;
   }

/*************************************************
* BER_Decoder Copy Constructor                   *
*************************************************/
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
   }

/*************************************************
* BER_Decoder Destructor                         *
*************************************************/
BER_Decoder::~BER_Decoder()
   {
   if(owns)
      delete source;
   source = 0;
   }

}
