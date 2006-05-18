/*************************************************
* DER Encoder Header File                        *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_DER_ENCODER_H__
#define BOTAN_DER_ENCODER_H__

#include <botan/asn1_oid.h>
#include <vector>

namespace Botan {

/*************************************************
* General DER Encoding Object                    *
*************************************************/
class DER_Encoder
   {
   public:
      SecureVector<byte> get_contents();

      DER_Encoder& start_sequence(ASN1_Tag, ASN1_Tag = CONTEXT_SPECIFIC);
      DER_Encoder& end_sequence(ASN1_Tag, ASN1_Tag = CONTEXT_SPECIFIC);
      DER_Encoder& start_set(ASN1_Tag, ASN1_Tag = CONTEXT_SPECIFIC);
      DER_Encoder& end_set(ASN1_Tag, ASN1_Tag = CONTEXT_SPECIFIC);

      DER_Encoder& start_sequence();
      DER_Encoder& end_sequence();
      DER_Encoder& start_set();
      DER_Encoder& end_set();

      DER_Encoder& start_explicit(ASN1_Tag, ASN1_Tag = CONTEXT_SPECIFIC);
      DER_Encoder& end_explicit(ASN1_Tag, ASN1_Tag = CONTEXT_SPECIFIC);

      DER_Encoder& add_raw_octets(const byte[], u32bit);
      DER_Encoder& add_raw_octets(const MemoryRegion<byte>&);

      DER_Encoder& encode_null();
      DER_Encoder& encode(bool);
      DER_Encoder& encode(u32bit);
      DER_Encoder& encode(const class BigInt&);
      DER_Encoder& encode(const MemoryRegion<byte>&, ASN1_Tag);
      DER_Encoder& encode(const byte[], u32bit, ASN1_Tag);

      DER_Encoder& encode(bool, ASN1_Tag, ASN1_Tag = CONTEXT_SPECIFIC);
      DER_Encoder& encode(u32bit, ASN1_Tag, ASN1_Tag = CONTEXT_SPECIFIC);
      DER_Encoder& encode(const class BigInt&, ASN1_Tag,
                          ASN1_Tag = CONTEXT_SPECIFIC);
      DER_Encoder& encode(const MemoryRegion<byte>&, ASN1_Tag,
                          ASN1_Tag, ASN1_Tag = CONTEXT_SPECIFIC);
      DER_Encoder& encode(const byte[], u32bit, ASN1_Tag,
                          ASN1_Tag, ASN1_Tag = CONTEXT_SPECIFIC);

      DER_Encoder& encode(const class ASN1_Object&);
      DER_Encoder& add_object(ASN1_Tag, ASN1_Tag, const byte[], u32bit);
      DER_Encoder& add_object(ASN1_Tag, ASN1_Tag, const MemoryRegion<byte>&);
      DER_Encoder& add_object(ASN1_Tag, ASN1_Tag, const std::string&);
      DER_Encoder& add_object(ASN1_Tag, ASN1_Tag, byte);

      DER_Encoder();
   private:
      DER_Encoder& start_cons(ASN1_Tag, ASN1_Tag, bool);
      DER_Encoder& end_cons(ASN1_Tag, ASN1_Tag);

      class DER_Sequence
         {
         public:
            ASN1_Tag tag_of() const;
            SecureVector<byte> get_contents();
            void add_bytes(const byte[], u32bit);
            DER_Sequence(ASN1_Tag, ASN1_Tag, bool = false);
         private:
            ASN1_Tag type_tag, class_tag;
            bool is_a_set;
            SecureVector<byte> contents;
            std::vector< SecureVector<byte> > set_contents;
         };
      SecureVector<byte> contents;
      std::vector<DER_Sequence> subsequences;
      u32bit sequence_level;
   };

}

#endif
