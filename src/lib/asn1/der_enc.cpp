/*
* DER Encoder
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/der_enc.h>
#include <botan/asn1_obj.h>
#include <botan/bigint.h>
#include <botan/loadstor.h>
#include <botan/internal/bit_ops.h>
#include <algorithm>

namespace Botan {

namespace {

/*
* DER encode an ASN.1 type tag
*/
secure_vector<uint8_t> encode_tag(ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   if((class_tag | 0xE0) != 0xE0)
      throw Encoding_Error("DER_Encoder: Invalid class tag " +
                           std::to_string(class_tag));

   secure_vector<uint8_t> encoded_tag;
   if(type_tag <= 30)
      encoded_tag.push_back(static_cast<uint8_t>(type_tag | class_tag));
   else
      {
      size_t blocks = high_bit(type_tag) + 6;
      blocks = (blocks - (blocks % 7)) / 7;

      BOTAN_ASSERT(blocks > 0, "Math works");

      encoded_tag.push_back(static_cast<uint8_t>(class_tag | 0x1F));
      for(size_t i = 0; i != blocks - 1; ++i)
         encoded_tag.push_back(0x80 | ((type_tag >> 7*(blocks-i-1)) & 0x7F));
      encoded_tag.push_back(type_tag & 0x7F);
      }

   return encoded_tag;
   }

/*
* DER encode an ASN.1 length field
*/
secure_vector<uint8_t> encode_length(size_t length)
   {
   secure_vector<uint8_t> encoded_length;
   if(length <= 127)
      encoded_length.push_back(static_cast<uint8_t>(length));
   else
      {
      const size_t bytes_needed = significant_bytes(length);

      encoded_length.push_back(static_cast<uint8_t>(0x80 | bytes_needed));

      for(size_t i = sizeof(length) - bytes_needed; i < sizeof(length); ++i)
         encoded_length.push_back(get_byte(i, length));
      }
   return encoded_length;
   }

}

/*
* Return the encoded SEQUENCE/SET
*/
secure_vector<uint8_t> DER_Encoder::DER_Sequence::get_contents()
   {
   const ASN1_Tag real_class_tag = ASN1_Tag(m_class_tag | CONSTRUCTED);

   if(m_type_tag == SET)
      {
      std::sort(m_set_contents.begin(), m_set_contents.end());
      for(size_t i = 0; i != m_set_contents.size(); ++i)
         m_contents += m_set_contents[i];
      m_set_contents.clear();
      }

   secure_vector<uint8_t> result;
   result += encode_tag(m_type_tag, real_class_tag);
   result += encode_length(m_contents.size());
   result += m_contents;
   m_contents.clear();

   return result;
   }

/*
* Add an encoded value to the SEQUENCE/SET
*/
void DER_Encoder::DER_Sequence::add_bytes(const uint8_t data[], size_t length)
   {
   if(m_type_tag == SET)
      m_set_contents.push_back(secure_vector<uint8_t>(data, data + length));
   else
      m_contents += std::make_pair(data, length);
   }

/*
* Return the type and class taggings
*/
ASN1_Tag DER_Encoder::DER_Sequence::tag_of() const
   {
   return ASN1_Tag(m_type_tag | m_class_tag);
   }

/*
* DER_Sequence Constructor
*/
DER_Encoder::DER_Sequence::DER_Sequence(ASN1_Tag t1, ASN1_Tag t2) :
   m_type_tag(t1), m_class_tag(t2)
   {
   }

/*
* Return the encoded contents
*/
secure_vector<uint8_t> DER_Encoder::get_contents()
   {
   if(m_subsequences.size() != 0)
      throw Invalid_State("DER_Encoder: Sequence hasn't been marked done");

   secure_vector<uint8_t> output;
   std::swap(output, m_contents);
   return output;
   }

/*
* Start a new ASN.1 SEQUENCE/SET/EXPLICIT
*/
DER_Encoder& DER_Encoder::start_cons(ASN1_Tag type_tag,
                                     ASN1_Tag class_tag)
   {
   m_subsequences.push_back(DER_Sequence(type_tag, class_tag));
   return (*this);
   }

/*
* Finish the current ASN.1 SEQUENCE/SET/EXPLICIT
*/
DER_Encoder& DER_Encoder::end_cons()
   {
   if(m_subsequences.empty())
      throw Invalid_State("DER_Encoder::end_cons: No such sequence");

   secure_vector<uint8_t> seq = m_subsequences[m_subsequences.size()-1].get_contents();
   m_subsequences.pop_back();
   raw_bytes(seq);
   return (*this);
   }

/*
* Start a new ASN.1 EXPLICIT encoding
*/
DER_Encoder& DER_Encoder::start_explicit(uint16_t type_no)
   {
   ASN1_Tag type_tag = static_cast<ASN1_Tag>(type_no);

   if(type_tag == SET)
      throw Internal_Error("DER_Encoder.start_explicit(SET); cannot perform");

   return start_cons(type_tag, CONTEXT_SPECIFIC);
   }

/*
* Finish the current ASN.1 EXPLICIT encoding
*/
DER_Encoder& DER_Encoder::end_explicit()
   {
   return end_cons();
   }

/*
* Write raw bytes into the stream
*/
DER_Encoder& DER_Encoder::raw_bytes(const secure_vector<uint8_t>& val)
   {
   return raw_bytes(val.data(), val.size());
   }

DER_Encoder& DER_Encoder::raw_bytes(const std::vector<uint8_t>& val)
   {
   return raw_bytes(val.data(), val.size());
   }

/*
* Write raw bytes into the stream
*/
DER_Encoder& DER_Encoder::raw_bytes(const uint8_t bytes[], size_t length)
   {
   if(m_subsequences.size())
      m_subsequences[m_subsequences.size()-1].add_bytes(bytes, length);
   else
      m_contents += std::make_pair(bytes, length);

   return (*this);
   }

/*
* Encode a NULL object
*/
DER_Encoder& DER_Encoder::encode_null()
   {
   return add_object(NULL_TAG, UNIVERSAL, nullptr, 0);
   }

/*
* DER encode a BOOLEAN
*/
DER_Encoder& DER_Encoder::encode(bool is_true)
   {
   return encode(is_true, BOOLEAN, UNIVERSAL);
   }

/*
* DER encode a small INTEGER
*/
DER_Encoder& DER_Encoder::encode(size_t n)
   {
   return encode(BigInt(n), INTEGER, UNIVERSAL);
   }

/*
* DER encode a small INTEGER
*/
DER_Encoder& DER_Encoder::encode(const BigInt& n)
   {
   return encode(n, INTEGER, UNIVERSAL);
   }

/*
* DER encode an OCTET STRING or BIT STRING
*/
DER_Encoder& DER_Encoder::encode(const secure_vector<uint8_t>& bytes,
                                 ASN1_Tag real_type)
   {
   return encode(bytes.data(), bytes.size(),
                 real_type, real_type, UNIVERSAL);
   }

/*
* DER encode an OCTET STRING or BIT STRING
*/
DER_Encoder& DER_Encoder::encode(const std::vector<uint8_t>& bytes,
                                 ASN1_Tag real_type)
   {
   return encode(bytes.data(), bytes.size(),
                 real_type, real_type, UNIVERSAL);
   }

/*
* Encode this object
*/
DER_Encoder& DER_Encoder::encode(const uint8_t bytes[], size_t length,
                                 ASN1_Tag real_type)
   {
   return encode(bytes, length, real_type, real_type, UNIVERSAL);
   }

/*
* DER encode a BOOLEAN
*/
DER_Encoder& DER_Encoder::encode(bool is_true,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   uint8_t val = is_true ? 0xFF : 0x00;
   return add_object(type_tag, class_tag, &val, 1);
   }

/*
* DER encode a small INTEGER
*/
DER_Encoder& DER_Encoder::encode(size_t n,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   return encode(BigInt(n), type_tag, class_tag);
   }

/*
* DER encode an INTEGER
*/
DER_Encoder& DER_Encoder::encode(const BigInt& n,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   if(n == 0)
      return add_object(type_tag, class_tag, 0);

   bool extra_zero = (n.bits() % 8 == 0);
   secure_vector<uint8_t> contents(extra_zero + n.bytes());
   BigInt::encode(&contents[extra_zero], n);
   if(n < 0)
      {
      for(size_t i = 0; i != contents.size(); ++i)
         contents[i] = ~contents[i];
      for(size_t i = contents.size(); i > 0; --i)
         if(++contents[i-1])
            break;
      }

   return add_object(type_tag, class_tag, contents);
   }

/*
* DER encode an OCTET STRING or BIT STRING
*/
DER_Encoder& DER_Encoder::encode(const secure_vector<uint8_t>& bytes,
                                 ASN1_Tag real_type,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   return encode(bytes.data(), bytes.size(),
                 real_type, type_tag, class_tag);
   }

/*
* DER encode an OCTET STRING or BIT STRING
*/
DER_Encoder& DER_Encoder::encode(const std::vector<uint8_t>& bytes,
                                 ASN1_Tag real_type,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   return encode(bytes.data(), bytes.size(),
                 real_type, type_tag, class_tag);
   }

/*
* DER encode an OCTET STRING or BIT STRING
*/
DER_Encoder& DER_Encoder::encode(const uint8_t bytes[], size_t length,
                                 ASN1_Tag real_type,
                                 ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   if(real_type != OCTET_STRING && real_type != BIT_STRING)
      throw Invalid_Argument("DER_Encoder: Invalid tag for byte/bit string");

   if(real_type == BIT_STRING)
      {
      secure_vector<uint8_t> encoded;
      encoded.push_back(0);
      encoded += std::make_pair(bytes, length);
      return add_object(type_tag, class_tag, encoded);
      }
   else
      return add_object(type_tag, class_tag, bytes, length);
   }

/*
* Conditionally write some values to the stream
*/
DER_Encoder& DER_Encoder::encode_if(bool cond, DER_Encoder& codec)
   {
   if(cond)
      return raw_bytes(codec.get_contents());
   return (*this);
   }

DER_Encoder& DER_Encoder::encode_if(bool cond, const ASN1_Object& obj)
   {
   if(cond)
      encode(obj);
   return (*this);
   }

/*
* Request for an object to encode itself
*/
DER_Encoder& DER_Encoder::encode(const ASN1_Object& obj)
   {
   obj.encode_into(*this);
   return (*this);
   }

/*
* Write the encoding of the byte(s)
*/
DER_Encoder& DER_Encoder::add_object(ASN1_Tag type_tag, ASN1_Tag class_tag,
                                     const uint8_t rep[], size_t length)
   {
   secure_vector<uint8_t> buffer;
   buffer += encode_tag(type_tag, class_tag);
   buffer += encode_length(length);
   buffer += std::make_pair(rep, length);

   return raw_bytes(buffer);
   }

/*
* Write the encoding of the byte(s)
*/
DER_Encoder& DER_Encoder::add_object(ASN1_Tag type_tag, ASN1_Tag class_tag,
                                     const std::string& rep_str)
   {
   const uint8_t* rep = reinterpret_cast<const uint8_t*>(rep_str.data());
   const size_t rep_len = rep_str.size();
   return add_object(type_tag, class_tag, rep, rep_len);
   }

/*
* Write the encoding of the byte
*/
DER_Encoder& DER_Encoder::add_object(ASN1_Tag type_tag,
                                     ASN1_Tag class_tag, uint8_t rep)
   {
   return add_object(type_tag, class_tag, &rep, 1);
   }

}
