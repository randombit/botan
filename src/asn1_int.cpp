/*************************************************
* ASN.1 Internals Source File                    *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/asn1_int.h>
#include <botan/der_enc.h>
#include <botan/data_src.h>
#include <botan/parsing.h>

namespace Botan {

/*************************************************
* BER Decoding Exceptions                        *
*************************************************/
BER_Decoding_Error::BER_Decoding_Error(const std::string& str) :
   Decoding_Error("BER: " + str) {}

BER_Bad_Tag::BER_Bad_Tag(const std::string& str, ASN1_Tag tag) :
      BER_Decoding_Error(str + ": " + to_string(tag)) {}

BER_Bad_Tag::BER_Bad_Tag(const std::string& str,
                         ASN1_Tag tag1, ASN1_Tag tag2) :
   BER_Decoding_Error(str + ": " + to_string(tag1) + "/" + to_string(tag2)) {}

namespace ASN1 {

/*************************************************
* Put some arbitrary bytes into a SEQUENCE       *
*************************************************/
SecureVector<byte> put_in_sequence(const MemoryRegion<byte>& contents)
   {
   DER_Encoder encoder;
   encoder.start_sequence();
   encoder.add_raw_octets(contents);
   encoder.end_sequence();
   return encoder.get_contents();
   }

/*************************************************
* Do heuristic tests for BER data                *
*************************************************/
bool maybe_BER(DataSource& source)
   {
   byte first_byte;
   if(!source.peek_byte(first_byte))
      throw Stream_IO_Error("ASN1::maybe_BER: Source was empty");

   if(first_byte == (SEQUENCE | CONSTRUCTED))
      return true;
   return false;
   }

}

}
