/*
* DER Encoder
* (C) 1999-2007,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/der_enc.h>

#include <botan/asn1_obj.h>
#include <botan/bigint.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <algorithm>

namespace Botan {

namespace {

/*
* DER encode an ASN.1 type tag
*/
void encode_tag(std::vector<uint8_t>& encoded_tag, ASN1_Type type_tag_e, ASN1_Class class_tag_e) {
   const uint32_t type_tag = static_cast<uint32_t>(type_tag_e);
   const uint32_t class_tag = static_cast<uint32_t>(class_tag_e);

   if((class_tag | 0xE0) != 0xE0) {
      throw Encoding_Error(fmt("DER_Encoder: Invalid class tag {}", std::to_string(class_tag)));
   }

   if(type_tag <= 30) {
      encoded_tag.push_back(static_cast<uint8_t>(type_tag | class_tag));
   } else {
      size_t blocks = high_bit(static_cast<uint32_t>(type_tag)) + 6;
      blocks = (blocks - (blocks % 7)) / 7;

      BOTAN_ASSERT_NOMSG(blocks > 0);

      encoded_tag.push_back(static_cast<uint8_t>(class_tag | 0x1F));
      for(size_t i = 0; i != blocks - 1; ++i) {
         encoded_tag.push_back(0x80 | ((type_tag >> 7 * (blocks - i - 1)) & 0x7F));
      }
      encoded_tag.push_back(type_tag & 0x7F);
   }
}

/*
* DER encode an ASN.1 length field
*/
void encode_length(std::vector<uint8_t>& encoded_length, size_t length) {
   if(length <= 127) {
      encoded_length.push_back(static_cast<uint8_t>(length));
   } else {
      const size_t bytes_needed = significant_bytes(length);

      encoded_length.push_back(static_cast<uint8_t>(0x80 | bytes_needed));

      for(size_t i = sizeof(length) - bytes_needed; i < sizeof(length); ++i) {
         encoded_length.push_back(get_byte_var(i, length));
      }
   }
}

}  // namespace

DER_Encoder::DER_Encoder(secure_vector<uint8_t>& vec) {
   m_append_output = [&vec](const uint8_t b[], size_t l) { vec.insert(vec.end(), b, b + l); };
}

DER_Encoder::DER_Encoder(std::vector<uint8_t>& vec) {
   m_append_output = [&vec](const uint8_t b[], size_t l) { vec.insert(vec.end(), b, b + l); };
}

/*
* Push the encoded SEQUENCE/SET to the encoder stream
*/
void DER_Encoder::DER_Sequence::push_contents(DER_Encoder& der) {
   const auto real_class_tag = m_class_tag | ASN1_Class::Constructed;

   if(m_type_tag == ASN1_Type::Set) {
      std::sort(m_set_contents.begin(), m_set_contents.end());
      for(const auto& set_elem : m_set_contents) {
         m_contents += set_elem;
      }
      m_set_contents.clear();
   }

   der.add_object(m_type_tag, real_class_tag, m_contents.data(), m_contents.size());
   m_contents.clear();
}

/*
* Add an encoded value to the SEQUENCE/SET
*/
void DER_Encoder::DER_Sequence::add_bytes(const uint8_t data[], size_t length) {
   if(m_type_tag == ASN1_Type::Set) {
      m_set_contents.push_back(secure_vector<uint8_t>(data, data + length));
   } else {
      m_contents += std::make_pair(data, length);
   }
}

void DER_Encoder::DER_Sequence::add_bytes(const uint8_t hdr[], size_t hdr_len, const uint8_t val[], size_t val_len) {
   if(m_type_tag == ASN1_Type::Set) {
      secure_vector<uint8_t> m;
      m.reserve(hdr_len + val_len);
      m += std::make_pair(hdr, hdr_len);
      m += std::make_pair(val, val_len);
      m_set_contents.push_back(std::move(m));
   } else {
      m_contents += std::make_pair(hdr, hdr_len);
      m_contents += std::make_pair(val, val_len);
   }
}

/*
* Return the type and class taggings
*/
uint32_t DER_Encoder::DER_Sequence::tag_of() const {
   return m_type_tag | m_class_tag;
}

/*
* DER_Sequence Constructor
*/
DER_Encoder::DER_Sequence::DER_Sequence(ASN1_Type t1, ASN1_Class t2) : m_type_tag(t1), m_class_tag(t2) {}

/*
* Return the encoded contents
*/
secure_vector<uint8_t> DER_Encoder::get_contents() {
   if(!m_subsequences.empty()) {
      throw Invalid_State("DER_Encoder: Sequence hasn't been marked done");
   }

   if(m_append_output) {
      throw Invalid_State("DER_Encoder Cannot get contents when using output vector");
   }

   secure_vector<uint8_t> output;
   std::swap(output, m_default_outbuf);
   return output;
}

std::vector<uint8_t> DER_Encoder::get_contents_unlocked() {
   if(!m_subsequences.empty()) {
      throw Invalid_State("DER_Encoder: Sequence hasn't been marked done");
   }

   if(m_append_output) {
      throw Invalid_State("DER_Encoder Cannot get contents when using output vector");
   }

   std::vector<uint8_t> output(m_default_outbuf.begin(), m_default_outbuf.end());
   m_default_outbuf.clear();
   return output;
}

/*
* Start a new ASN.1 SEQUENCE/SET/EXPLICIT
*/
DER_Encoder& DER_Encoder::start_cons(ASN1_Type type_tag, ASN1_Class class_tag) {
   m_subsequences.push_back(DER_Sequence(type_tag, class_tag));
   return (*this);
}

/*
* Finish the current ASN.1 SEQUENCE/SET/EXPLICIT
*/
DER_Encoder& DER_Encoder::end_cons() {
   if(m_subsequences.empty()) {
      throw Invalid_State("DER_Encoder::end_cons: No such sequence");
   }

   DER_Sequence last_seq = std::move(m_subsequences[m_subsequences.size() - 1]);
   m_subsequences.pop_back();
   last_seq.push_contents(*this);

   return (*this);
}

/*
* Start a new ASN.1 EXPLICIT encoding
*/
DER_Encoder& DER_Encoder::start_explicit(uint16_t type_no) {
   ASN1_Type type_tag = static_cast<ASN1_Type>(type_no);

   // This would confuse DER_Sequence
   if(type_tag == ASN1_Type::Set) {
      throw Internal_Error("DER_Encoder.start_explicit(SET) not supported");
   }

   return start_cons(type_tag, ASN1_Class::ContextSpecific);
}

/*
* Finish the current ASN.1 EXPLICIT encoding
*/
DER_Encoder& DER_Encoder::end_explicit() {
   return end_cons();
}

/*
* Write raw bytes into the stream
*/
DER_Encoder& DER_Encoder::raw_bytes(const uint8_t bytes[], size_t length) {
   if(!m_subsequences.empty()) {
      m_subsequences[m_subsequences.size() - 1].add_bytes(bytes, length);
   } else if(m_append_output) {
      m_append_output(bytes, length);
   } else {
      m_default_outbuf += std::make_pair(bytes, length);
   }

   return (*this);
}

/*
* Write the encoding of the byte(s)
*/
DER_Encoder& DER_Encoder::add_object(ASN1_Type type_tag, ASN1_Class class_tag, const uint8_t rep[], size_t length) {
   std::vector<uint8_t> hdr;
   encode_tag(hdr, type_tag, class_tag);
   encode_length(hdr, length);

   if(!m_subsequences.empty()) {
      m_subsequences[m_subsequences.size() - 1].add_bytes(hdr.data(), hdr.size(), rep, length);
   } else if(m_append_output) {
      m_append_output(hdr.data(), hdr.size());
      m_append_output(rep, length);
   } else {
      m_default_outbuf += hdr;
      m_default_outbuf += std::make_pair(rep, length);
   }

   return (*this);
}

/*
* Encode a NULL object
*/
DER_Encoder& DER_Encoder::encode_null() {
   return add_object(ASN1_Type::Null, ASN1_Class::Universal, nullptr, 0);
}

/*
* DER encode a BOOLEAN
*/
DER_Encoder& DER_Encoder::encode(bool is_true) {
   return encode(is_true, ASN1_Type::Boolean, ASN1_Class::Universal);
}

/*
* DER encode a small INTEGER
*/
DER_Encoder& DER_Encoder::encode(size_t n) {
   return encode(BigInt::from_u64(n), ASN1_Type::Integer, ASN1_Class::Universal);
}

/*
* DER encode a small INTEGER
*/
DER_Encoder& DER_Encoder::encode(const BigInt& n) {
   return encode(n, ASN1_Type::Integer, ASN1_Class::Universal);
}

/*
* Encode this object
*/
DER_Encoder& DER_Encoder::encode(const uint8_t bytes[], size_t length, ASN1_Type real_type) {
   return encode(bytes, length, real_type, real_type, ASN1_Class::Universal);
}

/*
* DER encode a BOOLEAN
*/
DER_Encoder& DER_Encoder::encode(bool is_true, ASN1_Type type_tag, ASN1_Class class_tag) {
   uint8_t val = is_true ? 0xFF : 0x00;
   return add_object(type_tag, class_tag, &val, 1);
}

/*
* DER encode a small INTEGER
*/
DER_Encoder& DER_Encoder::encode(size_t n, ASN1_Type type_tag, ASN1_Class class_tag) {
   return encode(BigInt::from_u64(n), type_tag, class_tag);
}

/*
* DER encode an INTEGER
*/
DER_Encoder& DER_Encoder::encode(const BigInt& n, ASN1_Type type_tag, ASN1_Class class_tag) {
   if(n == 0) {
      return add_object(type_tag, class_tag, 0);
   }

   const size_t extra_zero = (n.bits() % 8 == 0) ? 1 : 0;

   auto contents = n.serialize(n.bytes() + extra_zero);
   if(n < 0) {
      for(unsigned char& content : contents) {
         content = ~content;
      }
      for(size_t i = contents.size(); i > 0; --i) {
         if(++contents[i - 1]) {
            break;
         }
      }
   }

   return add_object(type_tag, class_tag, contents);
}

/*
* DER encode an OCTET STRING or BIT STRING
*/
DER_Encoder& DER_Encoder::encode(
   const uint8_t bytes[], size_t length, ASN1_Type real_type, ASN1_Type type_tag, ASN1_Class class_tag) {
   if(real_type != ASN1_Type::OctetString && real_type != ASN1_Type::BitString) {
      throw Invalid_Argument("DER_Encoder: Invalid tag for byte/bit string");
   }

   if(real_type == ASN1_Type::BitString) {
      secure_vector<uint8_t> encoded;
      encoded.push_back(0);
      encoded += std::make_pair(bytes, length);
      return add_object(type_tag, class_tag, encoded);
   } else {
      return add_object(type_tag, class_tag, bytes, length);
   }
}

DER_Encoder& DER_Encoder::encode(const ASN1_Object& obj) {
   obj.encode_into(*this);
   return (*this);
}

/*
* Write the encoding of the byte(s)
*/
DER_Encoder& DER_Encoder::add_object(ASN1_Type type_tag, ASN1_Class class_tag, std::string_view rep_str) {
   const uint8_t* rep = cast_char_ptr_to_uint8(rep_str.data());
   const size_t rep_len = rep_str.size();
   return add_object(type_tag, class_tag, rep, rep_len);
}

/*
* Write the encoding of the byte
*/
DER_Encoder& DER_Encoder::add_object(ASN1_Type type_tag, ASN1_Class class_tag, uint8_t rep) {
   return add_object(type_tag, class_tag, &rep, 1);
}

}  // namespace Botan
