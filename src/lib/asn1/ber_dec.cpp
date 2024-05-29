/*
* BER Decoder
* (C) 1999-2008,2015,2017,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ber_dec.h>

#include <botan/bigint.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <memory>

namespace Botan {

namespace {

/*
* This value is somewhat arbitrary. OpenSSL allows up to 128 nested
* indefinite length sequences. If you increase this, also increase the
* limit in the test in test_asn1.cpp
*/
const size_t ALLOWED_EOC_NESTINGS = 16;

/*
* BER decode an ASN.1 type tag
*/
size_t decode_tag(DataSource* ber, ASN1_Type& type_tag, ASN1_Class& class_tag) {
   uint8_t b;
   if(!ber->read_byte(b)) {
      type_tag = ASN1_Type::NoObject;
      class_tag = ASN1_Class::NoObject;
      return 0;
   }

   if((b & 0x1F) != 0x1F) {
      type_tag = ASN1_Type(b & 0x1F);
      class_tag = ASN1_Class(b & 0xE0);
      return 1;
   }

   size_t tag_bytes = 1;
   class_tag = ASN1_Class(b & 0xE0);

   size_t tag_buf = 0;
   while(true) {
      if(!ber->read_byte(b)) {
         throw BER_Decoding_Error("Long-form tag truncated");
      }
      if(tag_buf & 0xFF000000) {
         throw BER_Decoding_Error("Long-form tag overflowed 32 bits");
      }
      // This is required even by BER (see X.690 section 8.1.2.4.2 sentence c)
      if(tag_bytes == 0 && b == 0x80) {
         throw BER_Decoding_Error("Long form tag with leading zero");
      }
      ++tag_bytes;
      tag_buf = (tag_buf << 7) | (b & 0x7F);
      if((b & 0x80) == 0) {
         break;
      }
   }
   type_tag = ASN1_Type(tag_buf);
   return tag_bytes;
}

/*
* Find the EOC marker
*/
size_t find_eoc(DataSource* src, size_t allow_indef);

/*
* BER decode an ASN.1 length field
*/
size_t decode_length(DataSource* ber, size_t& field_size, size_t allow_indef) {
   uint8_t b;
   if(!ber->read_byte(b)) {
      throw BER_Decoding_Error("Length field not found");
   }
   field_size = 1;
   if((b & 0x80) == 0) {
      return b;
   }

   field_size += (b & 0x7F);
   if(field_size > 5) {
      throw BER_Decoding_Error("Length field is too large");
   }

   if(field_size == 1) {
      if(allow_indef == 0) {
         throw BER_Decoding_Error("Nested EOC markers too deep, rejecting to avoid stack exhaustion");
      } else {
         return find_eoc(ber, allow_indef - 1);
      }
   }

   size_t length = 0;

   for(size_t i = 0; i != field_size - 1; ++i) {
      if(get_byte<0>(length) != 0) {
         throw BER_Decoding_Error("Field length overflow");
      }
      if(!ber->read_byte(b)) {
         throw BER_Decoding_Error("Corrupted length field");
      }
      length = (length << 8) | b;
   }
   return length;
}

/*
* Find the EOC marker
*/
size_t find_eoc(DataSource* ber, size_t allow_indef) {
   secure_vector<uint8_t> buffer(BOTAN_DEFAULT_BUFFER_SIZE), data;

   while(true) {
      const size_t got = ber->peek(buffer.data(), buffer.size(), data.size());
      if(got == 0) {
         break;
      }

      data += std::make_pair(buffer.data(), got);
   }

   DataSource_Memory source(data);
   data.clear();

   size_t length = 0;
   while(true) {
      ASN1_Type type_tag;
      ASN1_Class class_tag;
      const size_t tag_size = decode_tag(&source, type_tag, class_tag);
      if(type_tag == ASN1_Type::NoObject) {
         break;
      }

      size_t length_size = 0;
      const size_t item_size = decode_length(&source, length_size, allow_indef);
      source.discard_next(item_size);

      if(auto new_len = checked_add(length, item_size, tag_size, length_size)) {
         length = new_len.value();
      } else {
         throw Decoding_Error("Integer overflow while decoding DER");
      }

      if(type_tag == ASN1_Type::Eoc && class_tag == ASN1_Class::Universal) {
         break;
      }
   }
   return length;
}

class DataSource_BERObject final : public DataSource {
   public:
      size_t read(uint8_t out[], size_t length) override {
         BOTAN_ASSERT_NOMSG(m_offset <= m_obj.length());
         const size_t got = std::min<size_t>(m_obj.length() - m_offset, length);
         copy_mem(out, m_obj.bits() + m_offset, got);
         m_offset += got;
         return got;
      }

      size_t peek(uint8_t out[], size_t length, size_t peek_offset) const override {
         BOTAN_ASSERT_NOMSG(m_offset <= m_obj.length());
         const size_t bytes_left = m_obj.length() - m_offset;

         if(peek_offset >= bytes_left) {
            return 0;
         }

         const size_t got = std::min(bytes_left - peek_offset, length);
         copy_mem(out, m_obj.bits() + m_offset + peek_offset, got);
         return got;
      }

      bool check_available(size_t n) override {
         BOTAN_ASSERT_NOMSG(m_offset <= m_obj.length());
         return (n <= (m_obj.length() - m_offset));
      }

      bool end_of_data() const override { return get_bytes_read() == m_obj.length(); }

      size_t get_bytes_read() const override { return m_offset; }

      explicit DataSource_BERObject(BER_Object&& obj) : m_obj(std::move(obj)), m_offset(0) {}

   private:
      BER_Object m_obj;
      size_t m_offset;
};

}  // namespace

/*
* Check if more objects are there
*/
bool BER_Decoder::more_items() const {
   if(m_source->end_of_data() && !m_pushed.is_set()) {
      return false;
   }
   return true;
}

/*
* Verify that no bytes remain in the source
*/
BER_Decoder& BER_Decoder::verify_end() {
   return verify_end("BER_Decoder::verify_end called, but data remains");
}

/*
* Verify that no bytes remain in the source
*/
BER_Decoder& BER_Decoder::verify_end(std::string_view err) {
   if(!m_source->end_of_data() || m_pushed.is_set()) {
      throw Decoding_Error(err);
   }
   return (*this);
}

/*
* Discard all the bytes remaining in the source
*/
BER_Decoder& BER_Decoder::discard_remaining() {
   uint8_t buf;
   while(m_source->read_byte(buf)) {}
   return (*this);
}

const BER_Object& BER_Decoder::peek_next_object() {
   if(!m_pushed.is_set()) {
      m_pushed = get_next_object();
   }

   return m_pushed;
}

/*
* Return the BER encoding of the next object
*/
BER_Object BER_Decoder::get_next_object() {
   BER_Object next;

   if(m_pushed.is_set()) {
      std::swap(next, m_pushed);
      return next;
   }

   for(;;) {
      ASN1_Type type_tag;
      ASN1_Class class_tag;
      decode_tag(m_source, type_tag, class_tag);
      next.set_tagging(type_tag, class_tag);
      if(next.is_set() == false) {  // no more objects
         return next;
      }

      size_t field_size;
      const size_t length = decode_length(m_source, field_size, ALLOWED_EOC_NESTINGS);
      if(!m_source->check_available(length)) {
         throw BER_Decoding_Error("Value truncated");
      }

      uint8_t* out = next.mutable_bits(length);
      if(m_source->read(out, length) != length) {
         throw BER_Decoding_Error("Value truncated");
      }

      if(next.tagging() == static_cast<uint32_t>(ASN1_Type::Eoc)) {
         continue;
      } else {
         break;
      }
   }

   return next;
}

/*
* Push a object back into the stream
*/
void BER_Decoder::push_back(const BER_Object& obj) {
   if(m_pushed.is_set()) {
      throw Invalid_State("BER_Decoder: Only one push back is allowed");
   }
   m_pushed = obj;
}

void BER_Decoder::push_back(BER_Object&& obj) {
   if(m_pushed.is_set()) {
      throw Invalid_State("BER_Decoder: Only one push back is allowed");
   }
   m_pushed = std::move(obj);
}

BER_Decoder BER_Decoder::start_cons(ASN1_Type type_tag, ASN1_Class class_tag) {
   BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, class_tag | ASN1_Class::Constructed);
   return BER_Decoder(std::move(obj), this);
}

/*
* Finish decoding a CONSTRUCTED type
*/
BER_Decoder& BER_Decoder::end_cons() {
   if(!m_parent) {
      throw Invalid_State("BER_Decoder::end_cons called with null parent");
   }
   if(!m_source->end_of_data()) {
      throw Decoding_Error("BER_Decoder::end_cons called with data left");
   }
   return (*m_parent);
}

BER_Decoder::BER_Decoder(BER_Object&& obj, BER_Decoder* parent) {
   m_data_src = std::make_unique<DataSource_BERObject>(std::move(obj));
   m_source = m_data_src.get();
   m_parent = parent;
}

/*
* BER_Decoder Constructor
*/
BER_Decoder::BER_Decoder(DataSource& src) {
   m_source = &src;
}

/*
* BER_Decoder Constructor
 */
BER_Decoder::BER_Decoder(const uint8_t data[], size_t length) {
   m_data_src = std::make_unique<DataSource_Memory>(data, length);
   m_source = m_data_src.get();
}

/*
* BER_Decoder Constructor
*/
BER_Decoder::BER_Decoder(const secure_vector<uint8_t>& data) {
   m_data_src = std::make_unique<DataSource_Memory>(data);
   m_source = m_data_src.get();
}

/*
* BER_Decoder Constructor
*/
BER_Decoder::BER_Decoder(const std::vector<uint8_t>& data) {
   m_data_src = std::make_unique<DataSource_Memory>(data.data(), data.size());
   m_source = m_data_src.get();
}

/*
* BER_Decoder Copy Constructor
*/
BER_Decoder::BER_Decoder(const BER_Decoder& other) {
   m_source = other.m_source;

   // take ownership
   std::swap(m_data_src, other.m_data_src);
   m_parent = other.m_parent;
}

/*
* Request for an object to decode itself
*/
BER_Decoder& BER_Decoder::decode(ASN1_Object& obj, ASN1_Type /*unused*/, ASN1_Class /*unused*/) {
   obj.decode_from(*this);
   return (*this);
}

/*
* Decode a BER encoded NULL
*/
BER_Decoder& BER_Decoder::decode_null() {
   BER_Object obj = get_next_object();
   obj.assert_is_a(ASN1_Type::Null, ASN1_Class::Universal);
   if(obj.length() > 0) {
      throw BER_Decoding_Error("NULL object had nonzero size");
   }
   return (*this);
}

BER_Decoder& BER_Decoder::decode_octet_string_bigint(BigInt& out) {
   secure_vector<uint8_t> out_vec;
   decode(out_vec, ASN1_Type::OctetString);
   out = BigInt::from_bytes(out_vec);
   return (*this);
}

/*
* Decode a BER encoded BOOLEAN
*/
BER_Decoder& BER_Decoder::decode(bool& out, ASN1_Type type_tag, ASN1_Class class_tag) {
   BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, class_tag);

   if(obj.length() != 1) {
      throw BER_Decoding_Error("BER boolean value had invalid size");
   }

   out = (obj.bits()[0]) ? true : false;
   return (*this);
}

/*
* Decode a small BER encoded INTEGER
*/
BER_Decoder& BER_Decoder::decode(size_t& out, ASN1_Type type_tag, ASN1_Class class_tag) {
   BigInt integer;
   decode(integer, type_tag, class_tag);

   if(integer.is_negative()) {
      throw BER_Decoding_Error("Decoded small integer value was negative");
   }

   if(integer.bits() > 32) {
      throw BER_Decoding_Error("Decoded integer value larger than expected");
   }

   out = 0;
   for(size_t i = 0; i != 4; ++i) {
      out = (out << 8) | integer.byte_at(3 - i);
   }

   return (*this);
}

/*
* Decode a small BER encoded INTEGER
*/
uint64_t BER_Decoder::decode_constrained_integer(ASN1_Type type_tag, ASN1_Class class_tag, size_t T_bytes) {
   if(T_bytes > 8) {
      throw BER_Decoding_Error("Can't decode small integer over 8 bytes");
   }

   BigInt integer;
   decode(integer, type_tag, class_tag);

   if(integer.bits() > 8 * T_bytes) {
      throw BER_Decoding_Error("Decoded integer value larger than expected");
   }

   uint64_t out = 0;
   for(size_t i = 0; i != 8; ++i) {
      out = (out << 8) | integer.byte_at(7 - i);
   }

   return out;
}

/*
* Decode a BER encoded INTEGER
*/
BER_Decoder& BER_Decoder::decode(BigInt& out, ASN1_Type type_tag, ASN1_Class class_tag) {
   BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, class_tag);

   if(obj.length() == 0) {
      out.clear();
   } else {
      const bool negative = (obj.bits()[0] & 0x80) ? true : false;

      if(negative) {
         secure_vector<uint8_t> vec(obj.bits(), obj.bits() + obj.length());
         for(size_t i = obj.length(); i > 0; --i) {
            if(vec[i - 1]--) {
               break;
            }
         }
         for(size_t i = 0; i != obj.length(); ++i) {
            vec[i] = ~vec[i];
         }
         out._assign_from_bytes(vec);
         out.flip_sign();
      } else {
         out._assign_from_bytes(obj.data());
      }
   }

   return (*this);
}

namespace {

template <typename Alloc>
void asn1_decode_binary_string(std::vector<uint8_t, Alloc>& buffer,
                               const BER_Object& obj,
                               ASN1_Type real_type,
                               ASN1_Type type_tag,
                               ASN1_Class class_tag) {
   obj.assert_is_a(type_tag, class_tag);

   if(real_type == ASN1_Type::OctetString) {
      buffer.assign(obj.bits(), obj.bits() + obj.length());
   } else {
      if(obj.length() == 0) {
         throw BER_Decoding_Error("Invalid BIT STRING");
      }
      if(obj.bits()[0] >= 8) {
         throw BER_Decoding_Error("Bad number of unused bits in BIT STRING");
      }

      buffer.resize(obj.length() - 1);

      if(obj.length() > 1) {
         copy_mem(buffer.data(), obj.bits() + 1, obj.length() - 1);
      }
   }
}

}  // namespace

/*
* BER decode a BIT STRING or OCTET STRING
*/
BER_Decoder& BER_Decoder::decode(secure_vector<uint8_t>& buffer,
                                 ASN1_Type real_type,
                                 ASN1_Type type_tag,
                                 ASN1_Class class_tag) {
   if(real_type != ASN1_Type::OctetString && real_type != ASN1_Type::BitString) {
      throw BER_Bad_Tag("Bad tag for {BIT,OCTET} STRING", static_cast<uint32_t>(real_type));
   }

   asn1_decode_binary_string(buffer, get_next_object(), real_type, type_tag, class_tag);
   return (*this);
}

BER_Decoder& BER_Decoder::decode(std::vector<uint8_t>& buffer,
                                 ASN1_Type real_type,
                                 ASN1_Type type_tag,
                                 ASN1_Class class_tag) {
   if(real_type != ASN1_Type::OctetString && real_type != ASN1_Type::BitString) {
      throw BER_Bad_Tag("Bad tag for {BIT,OCTET} STRING", static_cast<uint32_t>(real_type));
   }

   asn1_decode_binary_string(buffer, get_next_object(), real_type, type_tag, class_tag);
   return (*this);
}

}  // namespace Botan
