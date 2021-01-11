/*
* ASN.1 Internals
* (C) 1999-2007,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_obj.h>
#include <botan/der_enc.h>
#include <botan/data_src.h>
#include <botan/internal/stl_util.h>
#include <sstream>

namespace Botan {

std::vector<uint8_t> ASN1_Object::BER_encode() const
   {
   std::vector<uint8_t> output;
   DER_Encoder der(output);
   this->encode_into(der);
   return output;
   }

/*
* Check a type invariant on BER data
*/
void BER_Object::assert_is_a(ASN1_Type expected_type_tag, ASN1_Class expected_class_tag,
                             const std::string& descr) const
   {
   if(this->is_a(expected_type_tag, expected_class_tag) == false)
      {
      std::stringstream msg;

      msg << "Tag mismatch when decoding " << descr << " got ";

      if(m_class_tag == ASN1_Class::NO_OBJECT && m_type_tag == ASN1_Type::NO_OBJECT)
         {
         msg << "EOF";
         }
      else
         {
         if(m_class_tag == ASN1_Class::UNIVERSAL || m_class_tag == ASN1_Class::CONSTRUCTED)
            {
            msg << asn1_tag_to_string(m_type_tag);
            }
         else
            {
            msg << std::to_string(static_cast<uint32_t>(m_type_tag));
            }

         msg << "/" << asn1_class_to_string(m_class_tag);
         }

      msg << " expected ";

      if(expected_class_tag == ASN1_Class::UNIVERSAL || expected_class_tag == ASN1_Class::CONSTRUCTED)
         {
         msg << asn1_tag_to_string(expected_type_tag);
         }
      else
         {
         msg << std::to_string(static_cast<uint32_t>(expected_type_tag));
         }

      msg << "/" << asn1_class_to_string(expected_class_tag);

      throw BER_Decoding_Error(msg.str());
      }
   }

bool BER_Object::is_a(ASN1_Type expected_type_tag, ASN1_Class expected_class_tag) const
   {
   return (m_type_tag == expected_type_tag && m_class_tag == expected_class_tag);
   }

bool BER_Object::is_a(int expected_type_tag, ASN1_Class expected_class_tag) const
   {
   return is_a(ASN1_Type(expected_type_tag), expected_class_tag);
   }

void BER_Object::set_tagging(ASN1_Type type_tag, ASN1_Class class_tag)
   {
   m_type_tag = type_tag;
   m_class_tag = class_tag;
   }

std::string asn1_class_to_string(ASN1_Class type)
   {
   switch(type)
      {
      case ASN1_Class::UNIVERSAL:
         return "UNIVERSAL";
      case ASN1_Class::CONSTRUCTED:
         return "CONSTRUCTED";
      case ASN1_Class::CONTEXT_SPECIFIC:
         return "CONTEXT_SPECIFIC";
      case ASN1_Class::APPLICATION:
         return "APPLICATION";
      case ASN1_Class::PRIVATE:
         return "PRIVATE";
      case ASN1_Class::NO_OBJECT:
         return "NO_OBJECT";
      default:
         return "CLASS(" + std::to_string(static_cast<size_t>(type)) + ")";
      }
   }

std::string asn1_tag_to_string(ASN1_Type type)
   {
   switch(type)
      {
      case ASN1_Type::SEQUENCE:
         return "SEQUENCE";

      case ASN1_Type::SET:
         return "SET";

      case ASN1_Type::PRINTABLE_STRING:
         return "PRINTABLE STRING";

      case ASN1_Type::NUMERIC_STRING:
         return "NUMERIC STRING";

      case ASN1_Type::IA5_STRING:
         return "IA5 STRING";

      case ASN1_Type::T61_STRING:
         return "T61 STRING";

      case ASN1_Type::UTF8_STRING:
         return "UTF8 STRING";

      case ASN1_Type::VISIBLE_STRING:
         return "VISIBLE STRING";

      case ASN1_Type::BMP_STRING:
         return "BMP STRING";

      case ASN1_Type::UNIVERSAL_STRING:
         return "UNIVERSAL STRING";

      case ASN1_Type::UTC_TIME:
         return "UTC TIME";

      case ASN1_Type::GENERALIZED_TIME:
         return "GENERALIZED TIME";

      case ASN1_Type::OCTET_STRING:
         return "OCTET STRING";

      case ASN1_Type::BIT_STRING:
         return "BIT STRING";

      case ASN1_Type::ENUMERATED:
         return "ENUMERATED";

      case ASN1_Type::INTEGER:
         return "INTEGER";

      case ASN1_Type::NULL_TAG:
         return "NULL";

      case ASN1_Type::OBJECT_ID:
         return "OBJECT";

      case ASN1_Type::BOOLEAN:
         return "BOOLEAN";

      case ASN1_Type::NO_OBJECT:
         return "NO_OBJECT";

      default:
         return "TAG(" + std::to_string(static_cast<uint32_t>(type)) + ")";
      }
   }

/*
* BER Decoding Exceptions
*/
BER_Decoding_Error::BER_Decoding_Error(const std::string& str) :
   Decoding_Error("BER: " + str) {}

BER_Bad_Tag::BER_Bad_Tag(const std::string& str, uint32_t tagging) :
   BER_Decoding_Error(str + ": " + std::to_string(tagging)) {}

namespace ASN1 {

/*
* Put some arbitrary bytes into a SEQUENCE
*/
std::vector<uint8_t> put_in_sequence(const std::vector<uint8_t>& contents)
   {
   return ASN1::put_in_sequence(contents.data(), contents.size());
   }

std::vector<uint8_t> put_in_sequence(const uint8_t bits[], size_t len)
   {
   std::vector<uint8_t> output;
   DER_Encoder(output)
      .start_sequence()
         .raw_bytes(bits, len)
      .end_cons();
   return output;
   }

/*
* Convert a BER object into a string object
*/
std::string to_string(const BER_Object& obj)
   {
   return std::string(cast_uint8_ptr_to_char(obj.bits()),
                      obj.length());
   }

/*
* Do heuristic tests for BER data
*/
bool maybe_BER(DataSource& source)
   {
   uint8_t first_u8;
   if(!source.peek_byte(first_u8))
      {
      BOTAN_ASSERT_EQUAL(source.read_byte(first_u8), 0, "Expected EOF");
      throw Stream_IO_Error("ASN1::maybe_BER: Source was empty");
      }

   const auto cons_seq = static_cast<uint8_t>(ASN1_Class::CONSTRUCTED) | static_cast<uint8_t>(ASN1_Type::SEQUENCE);
   if(first_u8 == cons_seq)
      return true;
   return false;
   }

}

}
