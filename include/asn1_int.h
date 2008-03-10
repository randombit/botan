/*************************************************
* ASN.1 Internals Header File                    *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_ASN1_H__
#define BOTAN_ASN1_H__

#include <botan/secmem.h>
#include <botan/enums.h>
#include <botan/exceptn.h>

namespace Botan {

/*************************************************
* Basic ASN.1 Object Interface                   *
*************************************************/
class ASN1_Object
   {
   public:
      virtual void encode_into(class DER_Encoder&) const = 0;
      virtual void decode_from(class BER_Decoder&) = 0;
      virtual ~ASN1_Object() {}
   };

/*************************************************
* BER Encoded Object                             *
*************************************************/
class BER_Object
   {
   public:
      void assert_is_a(ASN1_Tag, ASN1_Tag);

      ASN1_Tag type_tag, class_tag;
      SecureVector<byte> value;
   };

/*************************************************
* ASN.1 Utility Functions                        *
*************************************************/
class DataSource;

namespace ASN1 {

SecureVector<byte> put_in_sequence(const MemoryRegion<byte>&);
std::string to_string(const BER_Object&);
bool maybe_BER(DataSource&);

}

/*************************************************
* General BER Decoding Error Exception           *
*************************************************/
struct BER_Decoding_Error : public Decoding_Error
   {
   BER_Decoding_Error(const std::string&);
   };

/*************************************************
* Exception For Incorrect BER Taggings           *
*************************************************/
struct BER_Bad_Tag : public BER_Decoding_Error
   {
   BER_Bad_Tag(const std::string&, ASN1_Tag);
   BER_Bad_Tag(const std::string&, ASN1_Tag, ASN1_Tag);
   };

}

#endif
