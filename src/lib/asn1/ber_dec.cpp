
/*
* BER Decoder
* (C) 1999-2008,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/loadstor.h>
#include <botan/internal/safeint.h>

namespace Botan {

namespace {

/*
* BER decode an ASN.1 type tag
*/
size_t decode_tag(DataSource* ber, ASN1_Tag& type_tag, ASN1_Tag& class_tag)
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

   size_t tag_bytes = 1;
   class_tag = ASN1_Tag(b & 0xE0);

   size_t tag_buf = 0;
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
size_t find_eoc(DataSource*);

/*
* BER decode an ASN.1 length field
*/
size_t decode_length(DataSource* ber, size_t& field_size)
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

   size_t length = 0;

   for(size_t i = 0; i != field_size - 1; ++i)
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
size_t decode_length(DataSource* ber)
   {
   size_t dummy;
   return decode_length(ber, dummy);
   }

/*
* Find the EOC marker
*/
size_t find_eoc(DataSource* ber)
   {
   secure_vector<byte> buffer(DEFAULT_BUFFERSIZE), data;

   while(true)
      {
      const size_t got = ber->peek(buffer.data(), buffer.size(), data.size());
      if(got == 0)
         break;

      data += std::make_pair(buffer.data(), got);
      }

   DataSource_Memory source(data);
   data.clear();

   size_t length = 0;
   while(true)
      {
      ASN1_Tag type_tag, class_tag;
      size_t tag_size = decode_tag(&source, type_tag, class_tag);
      if(type_tag == NO_OBJECT)
         break;

      size_t length_size = 0;
      size_t item_size = decode_length(&source, length_size);
      source.discard_next(item_size);

      length = BOTAN_CHECKED_ADD(length, item_size);
      length = BOTAN_CHECKED_ADD(length, tag_size);
      length = BOTAN_CHECKED_ADD(length, length_size);

      if(type_tag == EOC && class_tag == UNIVERSAL)
         break;
      }
   return length;
   }

}

/*
* Check a type invariant on BER data
*/
void BER_Object::assert_is_a(ASN1_Tag type_tag_, ASN1_Tag class_tag_)
   {
   if(type_tag != type_tag_ || class_tag != class_tag_)
      throw BER_Decoding_Error("Tag mismatch when decoding got " +
                               std::to_string(type_tag) + "/" +
                               std::to_string(class_tag) + " expected " +
                               std::to_string(type_tag_) + "/" +
                               std::to_string(class_tag_));
   }

/*
* Check if more objects are there
*/
bool BER_Decoder::more_items() const
   {
   if(m_source->end_of_data() && (m_pushed.type_tag == NO_OBJECT))
      return false;
   return true;
   }

/*
* Verify that no bytes remain in the source
*/
BER_Decoder& BER_Decoder::verify_end()
   {
   if(!m_source->end_of_data() || (m_pushed.type_tag != NO_OBJECT))
      throw Invalid_State("BER_Decoder::verify_end called, but data remains");
   return (*this);
   }

/*
* Save all the bytes remaining in the source
*/
BER_Decoder& BER_Decoder::raw_bytes(secure_vector<byte>& out)
   {
   out.clear();
   byte buf;
   while(m_source->read_byte(buf))
      out.push_back(buf);
   return (*this);
   }

BER_Decoder& BER_Decoder::raw_bytes(std::vector<byte>& out)
   {
   out.clear();
   byte buf;
   while(m_source->read_byte(buf))
      out.push_back(buf);
   return (*this);
   }

/*
* Discard all the bytes remaining in the source
*/
BER_Decoder& BER_Decoder::discard_remaining()
   {
   byte buf;
   while(m_source->read_byte(buf))
      ;
   return (*this);
   }

/*
* Return the BER encoding of the next object
*/
BER_Object BER_Decoder::get_next_object()
   {
   BER_Object next;

   if(m_pushed.type_tag != NO_OBJECT)
      {
      next = m_pushed;
      m_pushed.class_tag = m_pushed.type_tag = NO_OBJECT;
      return next;
      }

   decode_tag(m_source, next.type_tag, next.class_tag);
   if(next.type_tag == NO_OBJECT)
      return next;

   const size_t length = decode_length(m_source);
   if(!m_source->check_available(length))
      throw BER_Decoding_Error("Value truncated");

   next.value.resize(length);
   if(m_source->read(next.value.data(), length) != length)
      throw BER_Decoding_Error("Value truncated");

   if(next.type_tag == EOC && next.class_tag == UNIVERSAL)
      return get_next_object();

   return next;
   }

BER_Decoder& BER_Decoder::get_next(BER_Object& ber)
   {
   ber = get_next_object();
   return (*this);
   }

/*
* Push a object back into the stream
*/
void BER_Decoder::push_back(const BER_Object& obj)
   {
   if(m_pushed.type_tag != NO_OBJECT)
      throw Invalid_State("BER_Decoder: Only one push back is allowed");
   m_pushed = obj;
   }

/*
* Begin decoding a CONSTRUCTED type
*/
BER_Decoder BER_Decoder::start_cons(ASN1_Tag type_tag,
                                    ASN1_Tag class_tag)
   {
   BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, ASN1_Tag(class_tag | CONSTRUCTED));

   BER_Decoder result(obj.value.data(), obj.value.size());
   result.m_parent = this;
   return result;
   }

/*
* Finish decoding a CONSTRUCTED type
*/
BER_Decoder& BER_Decoder::end_cons()
   {
   if(!m_parent)
      throw Invalid_State("BER_Decoder::end_cons called with NULL parent");
   if(!m_source->end_of_data())
      throw Decoding_Error("BER_Decoder::end_cons called with data left");
   return (*m_parent);
   }

/*
* BER_Decoder Constructor
*/
BER_Decoder::BER_Decoder(DataSource& src)
   {
   m_source = &src;
   m_owns = false;
   m_pushed.type_tag = m_pushed.class_tag = NO_OBJECT;
   m_parent = nullptr;
   }

/*
* BER_Decoder Constructor
 */
BER_Decoder::BER_Decoder(const byte data[], size_t length)
   {
   m_source = new DataSource_Memory(data, length);
   m_owns = true;
   m_pushed.type_tag = m_pushed.class_tag = NO_OBJECT;
   m_parent = nullptr;
   }

/*
* BER_Decoder Constructor
*/
BER_Decoder::BER_Decoder(const secure_vector<byte>& data)
   {
   m_source = new DataSource_Memory(data);
   m_owns = true;
   m_pushed.type_tag = m_pushed.class_tag = NO_OBJECT;
   m_parent = nullptr;
   }

/*
* BER_Decoder Constructor
*/
BER_Decoder::BER_Decoder(const std::vector<byte>& data)
   {
   m_source = new DataSource_Memory(data.data(), data.size());
   m_owns = true;
   m_pushed.type_tag = m_pushed.class_tag = NO_OBJECT;
   m_parent = nullptr;
   }

/*
* BER_Decoder Copy Constructor
*/
BER_Decoder::BER_Decoder(const BER_Decoder& other)
   {
   m_source = other.m_source;
   m_owns = false;
   if(other.m_owns)
      {
      other.m_owns = false;
      m_owns = true;
      }
   m_pushed.type_tag = m_pushed.class_tag = NO_OBJECT;
   m_parent = other.m_parent;
   }

/*
* BER_Decoder Destructor
*/
BER_Decoder::~BER_Decoder()
   {
   if(m_owns)
      delete m_source;
   m_source = nullptr;
   }

/*
* Request for an object to decode itself
*/
BER_Decoder& BER_Decoder::decode(ASN1_Object& obj,
                                 ASN1_Tag, ASN1_Tag)
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
BER_Decoder& BER_Decoder::decode(size_t& out)
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

BER_Decoder& BER_Decoder::decode_octet_string_bigint(BigInt& out)
   {
   secure_vector<byte> out_vec;
   decode(out_vec, OCTET_STRING);
   out = BigInt::decode(out_vec.data(), out_vec.size());
   return (*this);
   }

std::vector<byte> BER_Decoder::get_next_octet_string()
   {
   std::vector<byte> out_vec;
   decode(out_vec, OCTET_STRING);
   return out_vec;
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
BER_Decoder& BER_Decoder::decode(size_t& out,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   BigInt integer;
   decode(integer, type_tag, class_tag);

   if(integer.bits() > 32)
      throw BER_Decoding_Error("Decoded integer value larger than expected");

   out = 0;
   for(size_t i = 0; i != 4; ++i)
      out = (out << 8) | integer.byte_at(3-i);

   return (*this);
   }

/*
* Decode a small BER encoded INTEGER
*/
u64bit BER_Decoder::decode_constrained_integer(ASN1_Tag type_tag,
                                               ASN1_Tag class_tag,
                                               size_t T_bytes)
   {
   if(T_bytes > 8)
      throw BER_Decoding_Error("Can't decode small integer over 8 bytes");

   BigInt integer;
   decode(integer, type_tag, class_tag);

   if(integer.bits() > 8*T_bytes)
      throw BER_Decoding_Error("Decoded integer value larger than expected");

   u64bit out = 0;
   for(size_t i = 0; i != 8; ++i)
      out = (out << 8) | integer.byte_at(7-i);

   return out;
   }

/*
* Decode a BER encoded INTEGER
*/
BER_Decoder& BER_Decoder::decode(BigInt& out,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, class_tag);

   if(obj.value.empty())
      out = 0;
   else
      {
      const bool negative = (obj.value[0] & 0x80) ? true : false;

      if(negative)
         {
         for(size_t i = obj.value.size(); i > 0; --i)
            if(obj.value[i-1]--)
               break;
         for(size_t i = 0; i != obj.value.size(); ++i)
            obj.value[i] = ~obj.value[i];
         }

      out = BigInt(&obj.value[0], obj.value.size());

      if(negative)
         out.flip_sign();
      }

   return (*this);
   }

/*
* BER decode a BIT STRING or OCTET STRING
*/
BER_Decoder& BER_Decoder::decode(secure_vector<byte>& out, ASN1_Tag real_type)
   {
   return decode(out, real_type, real_type, UNIVERSAL);
   }

/*
* BER decode a BIT STRING or OCTET STRING
*/
BER_Decoder& BER_Decoder::decode(std::vector<byte>& out, ASN1_Tag real_type)
   {
   return decode(out, real_type, real_type, UNIVERSAL);
   }

/*
* BER decode a BIT STRING or OCTET STRING
*/
BER_Decoder& BER_Decoder::decode(secure_vector<byte>& buffer,
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
      if(obj.value.empty())
         throw BER_Decoding_Error("Invalid BIT STRING");
      if(obj.value[0] >= 8)
         throw BER_Decoding_Error("Bad number of unused bits in BIT STRING");

      buffer.resize(obj.value.size() - 1);
      copy_mem(buffer.data(), &obj.value[1], obj.value.size() - 1);
      }
   return (*this);
   }

BER_Decoder& BER_Decoder::decode(std::vector<byte>& buffer,
                                 ASN1_Tag real_type,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   if(real_type != OCTET_STRING && real_type != BIT_STRING)
      throw BER_Bad_Tag("Bad tag for {BIT,OCTET} STRING", real_type);

   BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, class_tag);

   if(real_type == OCTET_STRING)
      buffer = unlock(obj.value);
   else
      {
      if(obj.value.empty())
         throw BER_Decoding_Error("Invalid BIT STRING");
      if(obj.value[0] >= 8)
         throw BER_Decoding_Error("Bad number of unused bits in BIT STRING");

      buffer.resize(obj.value.size() - 1);
      copy_mem(buffer.data(), &obj.value[1], obj.value.size() - 1);
      }
   return (*this);
   }

}
