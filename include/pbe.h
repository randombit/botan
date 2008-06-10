/*************************************************
* PBE Header File                                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_PBE_H__
#define BOTAN_PBE_H__

#include <botan/asn1_oid.h>
#include <botan/data_src.h>
#include <botan/filter.h>
#include <botan/rng.h>

namespace Botan {

/*************************************************
* Password Based Encryption                      *
*************************************************/
class BOTAN_DLL PBE : public Filter
   {
   public:
      virtual void set_key(const std::string&) = 0;
      virtual void new_params(RandomNumberGenerator& rng) = 0;

      virtual MemoryVector<byte> encode_params() const = 0;
      virtual void decode_params(DataSource&) = 0;

      virtual OID get_oid() const = 0;
   };

/*************************************************
* Get a PBE object                               *
*************************************************/
BOTAN_DLL PBE* get_pbe(const std::string&);
BOTAN_DLL PBE* get_pbe(const OID&, DataSource&);

}

#endif
