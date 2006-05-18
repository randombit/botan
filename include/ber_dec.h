/*************************************************
* BER Decoder Header File                        *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_BER_DECODER_H__
#define BOTAN_BER_DECODER_H__

#include <botan/asn1_oid.h>
#include <botan/bigint.h>
#include <botan/data_src.h>

namespace Botan {

/*************************************************
* BER Encoded Object                             *
*************************************************/
struct BER_Object
   {
   ASN1_Tag type_tag, class_tag;
   SecureVector<byte> value;
   };

/*************************************************
* BER Decoding Object                            *
*************************************************/
class BER_Decoder
   {
   public:
      bool more_items() const;
      void verify_end() const;
      SecureVector<byte> get_remaining();
      void discard_remaining();
      BER_Object get_next_object();
      void push_back(const BER_Object&);

      BER_Decoder& decode_null();
      BER_Decoder& decode(bool&);
      BER_Decoder& decode(u32bit&);
      BER_Decoder& decode(class BigInt&);
      BER_Decoder& decode(MemoryRegion<byte>&, ASN1_Tag);

      BER_Decoder& decode(bool&, ASN1_Tag, ASN1_Tag = CONTEXT_SPECIFIC);
      BER_Decoder& decode(u32bit&, ASN1_Tag, ASN1_Tag = CONTEXT_SPECIFIC);
      BER_Decoder& decode(class BigInt&,
                          ASN1_Tag, ASN1_Tag = CONTEXT_SPECIFIC);
      BER_Decoder& decode(MemoryRegion<byte>&, ASN1_Tag,
                          ASN1_Tag, ASN1_Tag = CONTEXT_SPECIFIC);

      BER_Decoder(DataSource&);
      BER_Decoder(const byte[], u32bit);
      BER_Decoder(const MemoryRegion<byte>&);
      BER_Decoder(const BER_Decoder&);
      ~BER_Decoder();
   private:
      BER_Decoder& operator=(const BER_Decoder&) { return (*this); }
      DataSource* source;
      BER_Object pushed;
      mutable bool owns;
   };

/*************************************************
* BER Decoding Functions                         *
*************************************************/
namespace BER {

void decode(BER_Decoder&, OID&);

BER_Decoder get_subsequence(BER_Decoder&);
BER_Decoder get_subset(BER_Decoder&);

BER_Decoder get_subsequence(BER_Decoder&, ASN1_Tag,
                            ASN1_Tag = CONTEXT_SPECIFIC);
BER_Decoder get_subset(BER_Decoder&, ASN1_Tag, ASN1_Tag = CONTEXT_SPECIFIC);

std::string to_string(const BER_Object&);
bool decode_optional_string(BER_Decoder&, MemoryRegion<byte>&,
                            ASN1_Tag, ASN1_Tag, ASN1_Tag);

/*************************************************
* Decode an OPTIONAL or DEFAULT element          *
*************************************************/
template<class T>
bool decode_optional(BER_Decoder& in, T& out,
                     ASN1_Tag type_tag, ASN1_Tag class_tag,
                     const T& default_value = T())
   {
   BER_Object obj = in.get_next_object();

   if(obj.type_tag == type_tag && obj.class_tag == class_tag)
      {
      if(class_tag & CONSTRUCTED)
         {
         BER_Decoder stored_value(obj.value);
         //BER::decode(stored_value, out);
         stored_value.decode(out);
         stored_value.verify_end();
         }
      else
         {
         in.push_back(obj);
         //BER::decode(in, out, type_tag, class_tag);
         in.decode(out, type_tag, class_tag);
         }
      return true;
      }
   else
      {
      out = default_value;
      in.push_back(obj);
      return false;
      }
   }

}

}

#endif
