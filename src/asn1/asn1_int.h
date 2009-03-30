/*
* ASN.1 Internals
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ASN1_H__
#define BOTAN_ASN1_H__

#include <botan/secmem.h>
#include <botan/exceptn.h>

namespace Botan {

/*
* ASN.1 Type and Class Tags
*/
enum ASN1_Tag {
   UNIVERSAL        = 0x00,
   APPLICATION      = 0x40,
   CONTEXT_SPECIFIC = 0x80,
   PRIVATE          = 0xC0,

   CONSTRUCTED      = 0x20,

   EOC              = 0x00,
   BOOLEAN          = 0x01,
   INTEGER          = 0x02,
   BIT_STRING       = 0x03,
   OCTET_STRING     = 0x04,
   NULL_TAG         = 0x05,
   OBJECT_ID        = 0x06,
   ENUMERATED       = 0x0A,
   SEQUENCE         = 0x10,
   SET              = 0x11,

   UTF8_STRING      = 0x0C,
   NUMERIC_STRING   = 0x12,
   PRINTABLE_STRING = 0x13,
   T61_STRING       = 0x14,
   IA5_STRING       = 0x16,
   VISIBLE_STRING   = 0x1A,
   BMP_STRING       = 0x1E,

   UTC_TIME         = 0x17,
   GENERALIZED_TIME = 0x18,

   NO_OBJECT        = 0xFF00,
   DIRECTORY_STRING = 0xFF01
};

/*
* Basic ASN.1 Object Interface
*/
class BOTAN_DLL ASN1_Object
   {
   public:
      virtual void encode_into(class DER_Encoder&) const = 0;
      virtual void decode_from(class BER_Decoder&) = 0;
      virtual ~ASN1_Object() {}
   };

/*
* BER Encoded Object
*/
class BOTAN_DLL BER_Object
   {
   public:
      void assert_is_a(ASN1_Tag, ASN1_Tag);

      ASN1_Tag type_tag, class_tag;
      SecureVector<byte> value;
   };

/*
* ASN.1 Utility Functions
*/
class DataSource;

namespace ASN1 {

SecureVector<byte> put_in_sequence(const MemoryRegion<byte>&);
std::string to_string(const BER_Object&);
bool maybe_BER(DataSource&);

}

/*
* General BER Decoding Error Exception
*/
struct BER_Decoding_Error : public Decoding_Error
   {
   BER_Decoding_Error(const std::string&);
   };

/*
* Exception For Incorrect BER Taggings
*/
struct BER_Bad_Tag : public BER_Decoding_Error
   {
   BER_Bad_Tag(const std::string&, ASN1_Tag);
   BER_Bad_Tag(const std::string&, ASN1_Tag, ASN1_Tag);
   };

}

#endif
