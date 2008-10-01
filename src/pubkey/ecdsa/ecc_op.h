/*************************************************
* ECDSA/ECKAEG Operations Header File            *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ECDSA_OPERATIONS_H__
#define BOTAN_ECDSA_OPERATIONS_H__

#include <botan/bigint.h>
#include <botan/point_gfp.h>

namespace Botan {

/*************************************************
* ECDSA Operation                               *
*************************************************/
class BOTAN_DLL ECDSA_Operation
   {
   public:
      virtual bool verify(const byte sig[], u32bit sig_len,
                          const byte msg[], u32bit msg_len) const = 0;

      virtual SecureVector<byte> sign(const byte message[],
                                      u32bit mess_len) const = 0;

      virtual ECDSA_Operation* clone() const = 0;

      virtual ~ECDSA_Operation() {}
   };

/*************************************************
* ECKAEG Operation                               *
*************************************************/
class BOTAN_DLL ECKAEG_Operation
   {
   public:
      virtual SecureVector<byte> agree(const PointGFp&) const = 0;
      virtual ECKAEG_Operation* clone() const = 0;
      virtual ~ECKAEG_Operation() {}
   };

}

#endif
