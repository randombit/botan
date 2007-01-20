/*************************************************
* X.509 Public Key Header File                   *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_X509_PUBLIC_KEY_H__
#define BOTAN_X509_PUBLIC_KEY_H__

#include <botan/pipe.h>
#include <botan/pk_keys.h>
#include <botan/alg_id.h>

namespace Botan {

/*************************************************
* X.509 Public Key Encoder                       *
*************************************************/
class X509_Encoder
   {
   public:
      virtual AlgorithmIdentifier alg_id() const = 0;
      virtual MemoryVector<byte> key_bits() const = 0;
      virtual ~X509_Encoder() {}
   };

/*************************************************
* X.509 Public Key Decoder                       *
*************************************************/
class X509_Decoder
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
void encode(const Public_Key&, Pipe&, X509_Encoding = PEM);
std::string PEM_encode(const Public_Key&);

Public_Key* load_key(DataSource&);
Public_Key* load_key(const std::string&);
Public_Key* load_key(const MemoryRegion<byte>&);

Public_Key* copy_key(const Public_Key&);

Key_Constraints find_constraints(const Public_Key&, Key_Constraints);

}

}

#endif
