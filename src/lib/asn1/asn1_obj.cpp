/*
* ASN.1 Internals
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_obj.h>
#include <botan/der_enc.h>
#include <botan/data_src.h>
#include <botan/internal/stl_util.h>

namespace Botan {

/*
* Check a type invariant on BER data
*/
void BER_Object::assert_is_a(ASN1_Tag type_tag_, ASN1_Tag class_tag_,
                             const std::string& descr) const
   {
   if(this->is_a(type_tag_, class_tag_) == false)
      {
      throw BER_Decoding_Error("Tag mismatch when decoding " + descr + " got " +
                               std::to_string(type_tag) + "/" +
                               std::to_string(class_tag) + " expected " +
                               std::to_string(type_tag_) + "/" +
                               std::to_string(class_tag_));
      }
   }

bool BER_Object::is_a(ASN1_Tag type_tag_, ASN1_Tag class_tag_) const
   {
   return (type_tag == type_tag_ && class_tag == class_tag_);
   }

bool BER_Object::is_a(int type_tag_, ASN1_Tag class_tag_) const
   {
   return is_a(ASN1_Tag(type_tag_), class_tag_);
   }

void BER_Object::set_tagging(ASN1_Tag t, ASN1_Tag c)
   {
   type_tag = t;
   class_tag = c;
   }

std::string asn1_tag_to_string(ASN1_Tag type)
   {
   switch(type)
      {
      case Botan::SEQUENCE:
         return "SEQUENCE";

      case Botan::SET:
         return "SET";

      case Botan::PRINTABLE_STRING:
         return "PRINTABLE STRING";

      case Botan::NUMERIC_STRING:
         return "NUMERIC STRING";

      case Botan::IA5_STRING:
         return "IA5 STRING";

      case Botan::T61_STRING:
         return "T61 STRING";

      case Botan::UTF8_STRING:
         return "UTF8 STRING";

      case Botan::VISIBLE_STRING:
         return "VISIBLE STRING";

      case Botan::BMP_STRING:
         return "BMP STRING";

      case Botan::UTC_TIME:
         return "UTC TIME";

      case Botan::GENERALIZED_TIME:
         return "GENERALIZED TIME";

      case Botan::OCTET_STRING:
         return "OCTET STRING";

      case Botan::BIT_STRING:
         return "BIT STRING";

      case Botan::ENUMERATED:
         return "ENUMERATED";

      case Botan::INTEGER:
         return "INTEGER";

      case Botan::NULL_TAG:
         return "NULL";

      case Botan::OBJECT_ID:
         return "OBJECT";

      case Botan::BOOLEAN:
         return "BOOLEAN";

      default:
         return "TAG(" + std::to_string(static_cast<size_t>(type)) + ")";
      }
   }

/*
* BER Decoding Exceptions
*/
BER_Decoding_Error::BER_Decoding_Error(const std::string& str) :
   Decoding_Error("BER: " + str) {}

BER_Bad_Tag::BER_Bad_Tag(const std::string& str, ASN1_Tag tag) :
      BER_Decoding_Error(str + ": " + std::to_string(tag)) {}

BER_Bad_Tag::BER_Bad_Tag(const std::string& str,
                         ASN1_Tag tag1, ASN1_Tag tag2) :
   BER_Decoding_Error(str + ": " + std::to_string(tag1) + "/" + std::to_string(tag2)) {}

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
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .raw_bytes(bits, len)
      .end_cons()
   .get_contents_unlocked();
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

   if(first_u8 == (SEQUENCE | CONSTRUCTED))
      return true;
   return false;
   }

}

}
