/*************************************************
* X.509 Public Key Header File                   *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_X509_PUBLIC_KEY_H__
#define BOTAN_X509_PUBLIC_KEY_H__

#include <botan/pipe.h>
#include <botan/pk_keys.h>
#include <botan/alg_id.h>
#include <botan/enums.h>

namespace Botan {

/*************************************************
* X.509 Public Key Encoder                       *
*************************************************/
class BOTAN_DLL X509_Encoder
   {
   public:
      virtual AlgorithmIdentifier alg_id() const = 0;
      virtual MemoryVector<byte> key_bits() const = 0;
      virtual ~X509_Encoder() {}
   };

/*************************************************
* X.509 Public Key Decoder                       *
*************************************************/
class BOTAN_DLL X509_Decoder
   {
   public:
      virtual void alg_id(const AlgorithmIdentifier&) = 0;
      virtual void key_bits(const MemoryRegion<byte>&) = 0;
      virtual ~X509_Decoder() {}
   };

namespace X509 {

/*************************************************
* X.509 Public Key Encoding/Decoding             *
*************************************************/
BOTAN_DLL void encode(const Public_Key&, Pipe&, X509_Encoding = PEM);
BOTAN_DLL std::string PEM_encode(const Public_Key&);

BOTAN_DLL Public_Key* load_key(DataSource&);
BOTAN_DLL Public_Key* load_key(const std::string&);
BOTAN_DLL Public_Key* load_key(const MemoryRegion<byte>&);

BOTAN_DLL Public_Key* copy_key(const Public_Key&);

BOTAN_DLL Key_Constraints find_constraints(const Public_Key&, Key_Constraints);

}

}

#endif
