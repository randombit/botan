/*
* BER Decoder
* (C) 1999-2008,2015,2017,2018,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ber_dec.h>

#include <botan/bigint.h>
#include <botan/data_src.h>
#include <botan/internal/asn1_utils.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <memory>

namespace Botan {

namespace {

bool is_constructed(ASN1_Class class_tag) {
   return (static_cast<uint32_t>(class_tag) & static_cast<uint32_t>(ASN1_Class::Constructed)) != 0;
}

/*
* BER decode an ASN.1 type tag
*/
size_t decode_tag(DataSource* ber, ASN1_Type& type_tag, ASN1_Class& class_tag) {
   auto b = ber->read_byte();

   if(!b) {
      type_tag = ASN1_Type::NoObject;
      class_tag = ASN1_Class::NoObject;
      return 0;
   }

   if((*b & 0x1F) != 0x1F) {
      type_tag = ASN1_Type(*b & 0x1F);
      class_tag = ASN1_Class(*b & 0xE0);
      return 1;
   }

   size_t tag_bytes = 1;
   class_tag = ASN1_Class(*b & 0xE0);

   uint32_t tag_buf = 0;
   while(true) {
      b = ber->read_byte();
      if(!b) {
         throw BER_Decoding_Error("Long-form tag truncated");
      }
      // Reject if shifting in another 7 bits would overflow the uint32_t tag
      if((tag_buf >> 25) != 0) {
         throw BER_Decoding_Error("Long-form tag overflowed 32 bits");
      }
      // This is required even by BER (see X.690 section 8.1.2.4.2 sentence c).
      // Bits 7-1 of the first subsequent octet must not be all zero; this rules
      // out both 0x80 (continuation with no data) and 0x00 (a long-form encoding
      // of tag value 0, which collides with the EOC marker).
      if(tag_bytes == 1 && (*b & 0x7F) == 0) {
         throw BER_Decoding_Error("Long form tag with leading zero");
      }
      ++tag_bytes;
      tag_buf = (tag_buf << 7) | (*b & 0x7F);
      if((*b & 0x80) == 0) {
         break;
      }
   }
   // Per X.690 8.1.2.2, tag values 0-30 shall be encoded in the short form.
   // Long-form encoding is reserved for tag values >= 31 (X.690 8.1.2.3).
   // This is unconditional and applies to BER as well as DER.
   if(tag_buf <= 30) {
      throw BER_Decoding_Error("Long-form tag encoding used for small tag value");
   }

   if(tag_buf == static_cast<uint32_t>(ASN1_Type::NoObject)) {
      throw BER_Decoding_Error("Tag value collides with internal sentinel");
   }

   // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
   type_tag = ASN1_Type(tag_buf);
   return tag_bytes;
}

/*
* Find the EOC marker by scanning TLVs via peek, without buffering.
* Returns the number of bytes before and including the EOC marker.
*/
size_t find_eoc(DataSource* src, size_t base_offset, size_t allow_indef);

/*
* Result of decoding a BER length field.
*
* If indefinite is true, indefinite-length encoding was used: content_length
* is the number of content bytes (excluding the 2-byte EOC marker) and the
* caller must consume the EOC bytes after reading the content.
*/
class BerDecodedLength final {
   public:
      BerDecodedLength(size_t content_length, size_t field_length) :
            BerDecodedLength(content_length, field_length, false) {}

      static BerDecodedLength indefinite(size_t content_length, size_t field_length) {
         return BerDecodedLength(content_length, field_length, true);
      }

      size_t content_length() const { return m_content_length; }

      // Length plus the EOC bytes if an indefinite length field
      size_t total_length() const { return m_indefinite ? m_content_length + 2 : m_content_length; }

      size_t field_length() const { return m_field_length; }

      bool indefinite_length() const { return m_indefinite; }

   private:
      BerDecodedLength(size_t content_length, size_t field_length, bool indefinite) :
            m_content_length(content_length), m_field_length(field_length), m_indefinite(indefinite) {}

      size_t m_content_length;
      size_t m_field_length;
      bool m_indefinite;
};

/*
* BER decode an ASN.1 length field
*/
BerDecodedLength decode_length(DataSource* ber, size_t allow_indef, bool der_mode, bool constructed) {
   uint8_t b = 0;
   if(ber->read_byte(b) == 0) {
      throw BER_Decoding_Error("Length field not found");
   }
   if((b & 0x80) == 0) {
      return BerDecodedLength(b, 1);
   }

   const size_t num_length_bytes = (b & 0x7F);
   if(num_length_bytes > 4) {
      throw BER_Decoding_Error("Length field is too large");
   }

   const size_t field_size = 1 + num_length_bytes;

   if(num_length_bytes == 0) {
      if(der_mode) {
         throw BER_Decoding_Error("Detected indefinite-length encoding in DER structure");
      } else if(!constructed) {
         // Indefinite length is only valid for constructed types (X.690 8.1.3.2)
         throw BER_Decoding_Error("Indefinite-length encoding used with non-constructed type");
      } else if(allow_indef == 0) {
         throw BER_Decoding_Error("Nested EOC markers too deep, rejecting to avoid stack exhaustion");
      } else {
         // find_eoc returns bytes up to and including the EOC marker.
         // Return the content length; the caller consumes the EOC separately.
         const size_t eoc_len = find_eoc(ber, /*base_offset=*/0, allow_indef - 1);
         if(eoc_len < 2) {
            throw BER_Decoding_Error("Invalid EOC encoding");
         }
         return BerDecodedLength::indefinite(eoc_len - 2, field_size);
      }
   }

   size_t length = 0;

   for(size_t i = 0; i != num_length_bytes; ++i) {
      if(ber->read_byte(b) == 0) {
         throw BER_Decoding_Error("Corrupted length field");
      }
      // Can't overflow since we already checked that num_length_bytes <= 4
      length = (length << 8) | b;
   }

   // DER requires shortest possible length encoding
   if(der_mode) {
      if(length < 128) {
         throw BER_Decoding_Error("Detected non-canonical length encoding in DER structure");
      }
      if(num_length_bytes > 1 && length < (size_t(1) << ((num_length_bytes - 1) * 8))) {
         throw BER_Decoding_Error("Detected non-canonical length encoding in DER structure");
      }
   }

   return BerDecodedLength(length, field_size);
}

/*
* Peek a tag from the source at the given offset without consuming any data.
* Returns the number of bytes consumed by the tag, or 0 on EOF.
*/
size_t peek_tag(DataSource* src, size_t offset, ASN1_Type& type_tag, ASN1_Class& class_tag) {
   uint8_t b = 0;
   if(src->peek(&b, 1, offset) == 0) {
      type_tag = ASN1_Type::NoObject;
      class_tag = ASN1_Class::NoObject;
      return 0;
   }

   if((b & 0x1F) != 0x1F) {
      type_tag = ASN1_Type(b & 0x1F);
      class_tag = ASN1_Class(b & 0xE0);
      return 1;
   }

   class_tag = ASN1_Class(b & 0xE0);
   size_t tag_bytes = 1;
   uint32_t tag_buf = 0;

   while(true) {
      if(src->peek(&b, 1, offset + tag_bytes) == 0) {
         throw BER_Decoding_Error("Long-form tag truncated");
      }
      // Reject if shifting in another 7 bits would overflow the uint32_t tag
      if((tag_buf >> 25) != 0) {
         throw BER_Decoding_Error("Long-form tag overflowed 32 bits");
      }
      // Required even by BER (X.690 section 8.1.2.4.2 sentence c).
      // Bits 7-1 of the first subsequent octet must not be all zero; this rules
      // out both 0x80 (continuation with no data) and 0x00 (a long-form encoding
      // of tag value 0, which collides with the EOC marker).
      if(tag_bytes == 1 && (b & 0x7F) == 0) {
         throw BER_Decoding_Error("Long form tag with leading zero");
      }
      ++tag_bytes;
      tag_buf = (tag_buf << 7) | (b & 0x7F);
      if((b & 0x80) == 0) {
         break;
      }
   }

   // Per X.690 8.1.2.2, tag values 0-30 shall be encoded in the short form.
   // Long-form encoding is reserved for tag values >= 31 (X.690 8.1.2.3).
   // This is unconditional and applies to BER as well as DER.
   if(tag_buf <= 30) {
      throw BER_Decoding_Error("Long-form tag encoding used for small tag value");
   }

   if(tag_buf == static_cast<uint32_t>(ASN1_Type::NoObject)) {
      throw BER_Decoding_Error("Tag value collides with internal sentinel");
   }

   // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
   type_tag = ASN1_Type(tag_buf);
   return tag_bytes;
}

/*
* Peek a length from the source at the given offset without consuming any data.
* Returns the decoded length and sets field_size to the number of bytes consumed.
* For indefinite-length encoding, recursively scans ahead to find the EOC marker.
*/
size_t peek_length(DataSource* src, size_t offset, size_t& field_size, size_t allow_indef, bool constructed) {
   uint8_t b = 0;
   if(src->peek(&b, 1, offset) == 0) {
      throw BER_Decoding_Error("Length field not found");
   }

   field_size = 1;
   if((b & 0x80) == 0) {
      return b;
   }

   const size_t num_length_bytes = (b & 0x7F);
   field_size += num_length_bytes;
   if(field_size > 5) {
      throw BER_Decoding_Error("Length field is too large");
   }

   if(num_length_bytes == 0) {
      // Indefinite length is only valid for constructed types (X.690 8.1.3.2)
      if(!constructed) {
         throw BER_Decoding_Error("Indefinite-length encoding used with non-constructed type");
      }
      if(allow_indef == 0) {
         throw BER_Decoding_Error("Nested EOC markers too deep, rejecting to avoid stack exhaustion");
      }
      return find_eoc(src, offset + 1, allow_indef - 1);
   }

   size_t length = 0;
   for(size_t i = 0; i < num_length_bytes; ++i) {
      if(src->peek(&b, 1, offset + 1 + i) == 0) {
         throw BER_Decoding_Error("Corrupted length field");
      }
      if(get_byte<0>(length) != 0) {
         throw BER_Decoding_Error("Field length overflow");
      }
      length = (length << 8) | b;
   }
   return length;
}

/*
* Find the EOC marker by scanning TLVs via peek, without buffering.
* Returns the number of bytes before and including the EOC marker.
*/
size_t find_eoc(DataSource* src, size_t base_offset, size_t allow_indef) {
   size_t offset = base_offset;

   while(true) {
      ASN1_Type type_tag = ASN1_Type::NoObject;
      ASN1_Class class_tag = ASN1_Class::NoObject;
      const size_t tag_size = peek_tag(src, offset, type_tag, class_tag);
      if(type_tag == ASN1_Type::NoObject) {
         throw BER_Decoding_Error("Missing EOC marker in indefinite-length encoding");
      }

      size_t length_size = 0;
      const size_t item_size = peek_length(src, offset + tag_size, length_size, allow_indef, is_constructed(class_tag));

      if(auto new_offset = checked_add(offset, tag_size, length_size, item_size)) {
         offset = new_offset.value();
      } else {
         throw Decoding_Error("Integer overflow while scanning for EOC");
      }

      if(type_tag == ASN1_Type::Eoc && class_tag == ASN1_Class::Universal) {
         // Per X.690 8.1.5 the EOC marker is exactly two zero octets
         if(length_size != 1 || item_size != 0) {
            throw BER_Decoding_Error("EOC marker with non-zero length");
         }
         break;
      }
   }

   return offset - base_offset;
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

      explicit DataSource_BERObject(BER_Object&& obj) : m_obj(std::move(obj)) {}

   private:
      BER_Object m_obj;
      size_t m_offset = 0;
};

/*
* A non-owning DataSource over a span, used to drive tag/length decoding
* without copying the underlying buffer.
*/
class DataSource_Span final : public DataSource {
   public:
      size_t read(uint8_t out[], size_t length) override {
         const size_t got = std::min(m_buf.size() - m_offset, length);
         copy_mem(out, m_buf.data() + m_offset, got);
         m_offset += got;
         return got;
      }

      size_t peek(uint8_t out[], size_t length, size_t peek_offset) const override {
         if(peek_offset >= m_buf.size() - m_offset) {
            return 0;
         }
         const size_t got = std::min(m_buf.size() - m_offset - peek_offset, length);
         copy_mem(out, m_buf.data() + m_offset + peek_offset, got);
         return got;
      }

      bool check_available(size_t n) override { return n <= (m_buf.size() - m_offset); }

      bool end_of_data() const override { return m_offset == m_buf.size(); }

      size_t get_bytes_read() const override { return m_offset; }

      explicit DataSource_Span(std::span<const uint8_t> buf) : m_buf(buf) {}

   private:
      std::span<const uint8_t> m_buf;
      size_t m_offset = 0;
};

}  // namespace

BER_Decoder::~BER_Decoder() = default;

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
   m_pushed = BER_Object();
   uint8_t buf = 0;
   while(m_source->read_byte(buf) != 0) {}
   return (*this);
}

std::optional<uint8_t> BER_Decoder::read_next_byte() {
   BOTAN_ASSERT_NOMSG(m_source != nullptr);
   uint8_t b = 0;
   if(m_source->read_byte(b) != 0) {
      return b;
   } else {
      return {};
   }
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
      ASN1_Type type_tag = ASN1_Type::NoObject;
      ASN1_Class class_tag = ASN1_Class::NoObject;
      decode_tag(m_source, type_tag, class_tag);
      next.set_tagging(type_tag, class_tag);
      if(next.is_set() == false) {  // no more objects
         return next;
      }

      const size_t allow_indef = m_limits.allow_ber_encoding() ? m_limits.max_nested_indefinite_length() : 0;
      const bool der_mode = m_limits.require_der_encoding();
      const auto dl = decode_length(m_source, allow_indef, der_mode, is_constructed(class_tag));

      // Per X.690 8.1.5 the only valid EOC encoding is the two-octet
      // sequence 0x00 0x00. Reject any other length encoding on a tag of
      // (Eoc, Universal) before we consume the "content" bytes.
      if(type_tag == ASN1_Type::Eoc && class_tag == ASN1_Class::Universal &&
         (dl.content_length() != 0 || dl.indefinite_length())) {
         throw BER_Decoding_Error("EOC marker with non-zero length");
      }

      if(const auto max_size = m_limits.max_object_size(); max_size && dl.content_length() > *max_size) {
         throw BER_Decoding_Error("Encoded object exceeds maximum size");
      }

      if(!m_source->check_available(dl.total_length())) {
         throw BER_Decoding_Error("Value truncated");
      }

      uint8_t* out = next.mutable_bits(dl.content_length());
      if(m_source->read(out, dl.content_length()) != dl.content_length()) {
         throw BER_Decoding_Error("Value truncated");
      }

      if(dl.indefinite_length()) {
         // After reading the data consume the 2-byte EOC
         uint8_t eoc[2] = {0xFF, 0xFF};
         if(m_source->read(eoc, 2) != 2 || eoc[0] != 0x00 || eoc[1] != 0x00) {
            throw BER_Decoding_Error("Missing or malformed EOC marker");
         }
      }

      if(next.tagging() == static_cast<uint32_t>(ASN1_Type::Eoc)) {
         if(m_limits.require_der_encoding()) {
            throw BER_Decoding_Error("Detected EOC marker in DER structure");
         }
         // An EOC marker is only valid as an indefinite-length terminator, which
         // is consumed above when reading the indefinite-length object. A
         // standalone EOC is rejected unless the caller opted to tolerate it.
         if(m_limits.allow_standalone_eoc()) {
            continue;
         }
         throw BER_Decoding_Error("Encountered EOC marker outside of indefinite-length encoding");
      }

      break;
   }

   return next;
}

BER_Object BER_Decoder::get_next_value(size_t sizeofT, ASN1_Type type_tag, ASN1_Class class_tag) {
   const BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, class_tag);

   if(obj.length() != sizeofT) {
      throw BER_Decoding_Error("Size mismatch. Object value size is " + std::to_string(obj.length()) +
                               "; Output type size is " + std::to_string(sizeofT));
   }

   return obj;
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
   BER_Decoder child(std::move(obj), this);
   return child;
}

/*
* Finish decoding a CONSTRUCTED type
*/
BER_Decoder& BER_Decoder::end_cons() {
   if(m_parent == nullptr) {
      throw Invalid_State("BER_Decoder::end_cons called with null parent");
   }
   if(!m_source->end_of_data() || m_pushed.is_set()) {
      throw Decoding_Error("BER_Decoder::end_cons called with data left");
   }
   return (*m_parent);
}

BER_Decoder::BER_Decoder(BER_Object&& obj, BER_Decoder* parent) :
      m_limits(parent != nullptr ? parent->limits() : BER_Decoder::Limits::BER()), m_parent(parent) {
   m_data_src = std::make_unique<DataSource_BERObject>(std::move(obj));
   m_source = m_data_src.get();
}

/*
* BER_Decoder Constructor
*/
BER_Decoder::BER_Decoder(DataSource& src, Limits limits) : m_limits(limits), m_source(&src) {}

/*
* BER_Decoder Constructor
 */
BER_Decoder::BER_Decoder(std::span<const uint8_t> buf, Limits limits) : m_limits(limits) {
   m_data_src = std::make_unique<DataSource_Memory>(buf);
   m_source = m_data_src.get();
}

BER_Decoder::BER_Decoder(BER_Decoder&& other) noexcept = default;

BER_Decoder& BER_Decoder::operator=(BER_Decoder&&) noexcept = default;

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
   const BER_Object obj = get_next_object();
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
   const BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, class_tag);

   if(obj.length() != 1) {
      throw BER_Decoding_Error("BER boolean value had invalid size");
   }

   const uint8_t val = obj.bits()[0];

   // DER requires boolean values to be exactly 0x00 or 0xFF
   if(m_limits.require_der_encoding() && val != 0x00 && val != 0xFF) {
      throw BER_Decoding_Error("Detected non-canonical boolean encoding in DER structure");
   }

   out = (val != 0) ? true : false;

   return (*this);
}

/*
* Decode a small BER encoded INTEGER
*/
BER_Decoder& BER_Decoder::decode(size_t& out, ASN1_Type type_tag, ASN1_Class class_tag) {
   BigInt integer;
   decode(integer, type_tag, class_tag);

   if(integer.signum() < 0) {
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

   if(integer.is_negative()) {
      throw BER_Decoding_Error("Decoded small integer value was negative");
   }

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
   const BER_Object obj = get_next_object();
   obj.assert_is_a(type_tag, class_tag);

   // An INTEGER must have at least one content octet (X.690 section 8.3.1)
   if(obj.length() == 0) {
      throw BER_Decoding_Error("INTEGER encoding has no content octets");
   }

   // DER requires minimal INTEGER encoding (X.690 section 8.3.2)
   if(m_limits.require_der_encoding()) {
      if(obj.length() > 1) {
         if(obj.bits()[0] == 0x00 && (obj.bits()[1] & 0x80) == 0) {
            throw BER_Decoding_Error("Detected non-minimal INTEGER encoding in DER structure");
         }
         if(obj.bits()[0] == 0xFF && (obj.bits()[1] & 0x80) != 0) {
            throw BER_Decoding_Error("Detected non-minimal INTEGER encoding in DER structure");
         }
      }
   }

   const uint8_t first = obj.bits()[0];
   const bool negative = (first & 0x80) == 0x80;

   if(negative) {
      secure_vector<uint8_t> vec(obj.bits(), obj.bits() + obj.length());
      for(size_t i = obj.length(); i > 0; --i) {
         const bool gt0 = (vec[i - 1] > 0);
         vec[i - 1] -= 1;
         if(gt0) {
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

   return (*this);
}

namespace {

bool is_constructed(const BER_Object& obj) {
   return is_constructed(obj.class_tag());
}

template <typename Alloc>
void asn1_decode_binary_string(std::vector<uint8_t, Alloc>& buffer,
                               const BER_Object& obj,
                               ASN1_Type real_type,
                               ASN1_Type type_tag,
                               ASN1_Class class_tag,
                               bool require_der) {
   obj.assert_is_a(type_tag, class_tag);

   // DER requires BIT STRING and OCTET STRING to use primitive encoding
   if(require_der && is_constructed(obj)) {
      throw BER_Decoding_Error("Detected constructed string encoding in DER structure");
   }

   if(real_type == ASN1_Type::OctetString) {
      buffer.assign(obj.bits(), obj.bits() + obj.length());
   } else {
      if(obj.length() == 0) {
         throw BER_Decoding_Error("Invalid BIT STRING");
      }

      const uint8_t unused_bits = obj.bits()[0];

      if(unused_bits >= 8) {
         throw BER_Decoding_Error("Bad number of unused bits in BIT STRING");
      }

      // Empty BIT STRING with unused bits > 0 ...
      if(unused_bits > 0 && obj.length() < 2) {
         throw BER_Decoding_Error("Invalid BIT STRING");
      }

      // DER requires unused bits in BIT STRING to be zero (X.690 section 11.2.2)
      if(require_der && unused_bits > 0) {
         const uint8_t last_byte = obj.bits()[obj.length() - 1];
         if((last_byte & ((1 << unused_bits) - 1)) != 0) {
            throw BER_Decoding_Error("Detected non-zero padding bits in BIT STRING in DER structure");
         }
      }

      buffer.resize(obj.length() - 1);

      if(obj.length() > 1) {
         copy_mem(buffer.data(), obj.bits() + 1, obj.length() - 1);
      }
   }
}

uint8_t asn1_bitstring_unused_bits(const BER_Object& obj, ASN1_Type type_tag, ASN1_Class class_tag, bool require_der) {
   obj.assert_is_a(type_tag, class_tag);

   if(require_der && is_constructed(obj)) {
      throw BER_Decoding_Error("Detected constructed string encoding in DER structure");
   }

   if(obj.length() == 0) {
      throw BER_Decoding_Error("Invalid BIT STRING");
   }

   const uint8_t unused_bits = obj.bits()[0];

   if(unused_bits >= 8) {
      throw BER_Decoding_Error("Invalid number of unused bits in BIT STRING");
   }

   if(obj.length() == 1 && unused_bits != 0) {
      throw BER_Decoding_Error("Invalid BIT STRING");
   }

   if(require_der && unused_bits > 0) {
      const uint8_t last_byte = obj.bits()[obj.length() - 1];
      if((last_byte & ((1 << unused_bits) - 1)) != 0) {
         throw BER_Decoding_Error("Detected non-zero padding bits in BIT STRING in DER structure");
      }
   }

   return unused_bits;
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

   asn1_decode_binary_string(
      buffer, get_next_object(), real_type, type_tag, class_tag, m_limits.require_der_encoding());
   return (*this);
}

BER_Decoder& BER_Decoder::decode(std::vector<uint8_t>& buffer,
                                 ASN1_Type real_type,
                                 ASN1_Type type_tag,
                                 ASN1_Class class_tag) {
   if(real_type != ASN1_Type::OctetString && real_type != ASN1_Type::BitString) {
      throw BER_Bad_Tag("Bad tag for {BIT,OCTET} STRING", static_cast<uint32_t>(real_type));
   }

   asn1_decode_binary_string(
      buffer, get_next_object(), real_type, type_tag, class_tag, m_limits.require_der_encoding());
   return (*this);
}

BER_Decoder& BER_Decoder::decode_bitstring(ASN1_BitString& out, ASN1_Type type_tag, ASN1_Class class_tag) {
   const BER_Object obj = get_next_object();
   const uint8_t unused_bits = asn1_bitstring_unused_bits(obj, type_tag, class_tag, m_limits.require_der_encoding());

   std::vector<uint8_t> bits;
   bits.assign(obj.bits() + 1, obj.bits() + obj.length());

   if(unused_bits > 0 && !bits.empty()) {
      bits.back() &= static_cast<uint8_t>(0xFF << unused_bits);
   }

   out = ASN1_BitString(std::move(bits), unused_bits);
   return (*this);
}

BER_Decoder& BER_Decoder::decode_named_bitstring(uint64_t& out,
                                                 size_t width,
                                                 ASN1_Type type_tag,
                                                 ASN1_Class class_tag) {
   if(width > 64) {
      throw Invalid_Argument("BER_Decoder: Named BIT STRING width is too large");
   }

   ASN1_BitString bits;
   decode_bitstring(bits, type_tag, class_tag);

   if(bits.bit_length() > width) {
      throw BER_Decoding_Error("Named BIT STRING exceeds declared width");
   }

   if(m_limits.require_der_encoding() && bits.bit_length() > 0 && !bits.bit_at(bits.bit_length() - 1)) {
      throw BER_Decoding_Error("Named BIT STRING is not minimally encoded");
   }

   uint64_t decoded = 0;
   for(size_t bit = 0; bit != bits.bit_length(); ++bit) {
      if(bits.bit_at(bit)) {
         decoded |= uint64_t(1) << (width - 1 - bit);
      }
   }

   out = decoded;
   return (*this);
}

namespace ASN1 {

bool is_single_der_object(std::span<const uint8_t> bytes, ASN1_Type expected_type, ASN1_Class expected_class) {
   if(bytes.empty()) {
      return false;
   }

   try {
      DataSource_Span src(bytes);

      ASN1_Type type_tag = ASN1_Type::NoObject;
      ASN1_Class class_tag = ASN1_Class::NoObject;
      const size_t tag_bytes = decode_tag(&src, type_tag, class_tag);

      if(type_tag != expected_type || class_tag != expected_class) {
         return false;
      }

      const auto dl = decode_length(&src, /*allow_indef=*/0, /*der_mode=*/true, is_constructed(expected_class));

      const size_t header_bytes = tag_bytes + dl.field_length();
      if(header_bytes > bytes.size()) {
         return false;
      }
      return dl.content_length() == bytes.size() - header_bytes;
   } catch(Decoding_Error&) {
      return false;
   }
}

bool is_der_sequence_header(std::span<const uint8_t> bytes) {
   return is_single_der_object(bytes, ASN1_Type::Sequence, ASN1_Class::Universal | ASN1_Class::Constructed);
}

}  // namespace ASN1

}  // namespace Botan
