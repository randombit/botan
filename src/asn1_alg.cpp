/*************************************************
* Algorithm Identifier Source File               *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/asn1_obj.h>
#include <botan/oids.h>

namespace Botan {

/*************************************************
* Create an AlgorithmIdentifier                  *
*************************************************/
AlgorithmIdentifier::AlgorithmIdentifier(const OID& alg_id,
                                         const MemoryRegion<byte>& param) :
   oid(alg_id), parameters(param) { }

/*************************************************
* Create an AlgorithmIdentifier                  *
*************************************************/
AlgorithmIdentifier::AlgorithmIdentifier(const std::string& alg_id,
                                         const MemoryRegion<byte>& param) :
   oid(OIDS::lookup(alg_id)), parameters(param) { }

/*************************************************
* DER encode an AlgorithmIdentifier              *
*************************************************/
void AlgorithmIdentifier::encode_into(DER_Encoder& der) const
   {
   der.start_sequence()
      .encode(oid)
      .add_raw_octets(parameters)
   .end_sequence();
   }

/*************************************************
* Compare two AlgorithmIdentifiers               *
*************************************************/
bool operator==(const AlgorithmIdentifier& a1, const AlgorithmIdentifier& a2)
   {
   if(a1.oid != a2.oid)
      return false;
   if(a1.parameters != a2.parameters)
      return false;
   return true;
   }

/*************************************************
* Compare two AlgorithmIdentifiers               *
*************************************************/
bool operator!=(const AlgorithmIdentifier& a1, const AlgorithmIdentifier& a2)
   {
   return !(a1 == a2);
   }

namespace BER {

/*************************************************
* Decode a BER encoded AlgorithmIdentifier       *
*************************************************/
void decode(BER_Decoder& source, AlgorithmIdentifier& alg_id)
   {
   BER_Decoder sequence = BER::get_subsequence(source);
   BER::decode(sequence, alg_id.oid);
   alg_id.parameters = sequence.get_remaining();
   sequence.verify_end();
   }

}

}
