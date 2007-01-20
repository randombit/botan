/*************************************************
* KeyUsage Source File                           *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/asn1_obj.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/bit_ops.h>

namespace Botan {

namespace BER {

/*************************************************
* Decode a BER encoded KeyUsage                  *
*************************************************/
void decode(BER_Decoder& source, Key_Constraints& key_usage)
   {
   BER_Object obj = source.get_next_object();

   if(obj.type_tag != BIT_STRING || obj.class_tag != UNIVERSAL)
      throw BER_Bad_Tag("Bad tag for usage constraint",
                        obj.type_tag, obj.class_tag);
   if(obj.value.size() != 2 && obj.value.size() != 3)
      throw BER_Decoding_Error("Bad size for BITSTRING in usage constraint");
   if(obj.value[0] >= 8)
      throw BER_Decoding_Error("Invalid unused bits in usage constraint");

   const byte mask = (0xFF << obj.value[0]);
   obj.value[obj.value.size()-1] &= mask;

   u16bit usage = 0;
   for(u32bit j = 1; j != obj.value.size(); ++j)
      usage = (obj.value[j] << 8) | usage;

   key_usage = Key_Constraints(usage);
   }

}

}
