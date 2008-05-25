/*************************************************
* EAC CVC Public Key Header File                 *
* (C) 2008 FlexSecure Gmbh                       *
*          Falko Strenzke                        *
*          strenzke@flexsecure.de                *
*************************************************/

#ifndef BOTAN_EAC1_1_CVC_PUBLIC_KEY_H__
#define BOTAN_EAC1_1_CVC_PUBLIC_KEY_H__

#include <botan/pipe.h>
#include <botan/pk_keys.h>
#include <botan/alg_id.h>

namespace Botan {

/*************************************************
    * EAC CVC Public Key Encoder                       *
*************************************************/
    class EAC1_1_CVC_Encoder
    {
        public:
            virtual MemoryVector<byte> public_key(AlgorithmIdentifier const&) const = 0;
            virtual ~EAC1_1_CVC_Encoder() {}
    };

/*************************************************
    * EAC CVC Public Key Decoder                       *
*************************************************/
    class EAC1_1_CVC_Decoder
    {
        public:
            virtual AlgorithmIdentifier const public_key(const MemoryRegion<byte>&) = 0;
            virtual ~EAC1_1_CVC_Decoder() {}
    };
}
#endif
