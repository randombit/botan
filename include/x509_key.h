/*************************************************
* X.509 Public Key Header File                   *
* (C) 1999-2006 The Botan Project                *
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

/*************************************************
* X.509 Public Key                               *
*************************************************/
class X509_PublicKey : public virtual PK_Key
   {
   public:
      u64bit key_id() const;

      virtual X509_Encoder* x509_encoder() const = 0;
      virtual X509_Decoder* x509_decoder() = 0;
      virtual ~X509_PublicKey() {}
   };

namespace X509 {

/*************************************************
* X.509 Public Key Encoding/Decoding             *
*************************************************/
void encode(const X509_PublicKey&, Pipe&, X509_Encoding = PEM);
std::string PEM_encode(const X509_PublicKey&);

X509_PublicKey* load_key(DataSource&);
X509_PublicKey* load_key(const std::string&);
X509_PublicKey* load_key(const MemoryRegion<byte>&);

X509_PublicKey* copy_key(const X509_PublicKey&);

Key_Constraints find_constraints(const X509_PublicKey&, Key_Constraints);

}

}

#endif
