/*************************************************
* X.509 Public Key Header File                   *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_X509_PUBLIC_KEY_H__
#define BOTAN_X509_PUBLIC_KEY_H__

#include <botan/pipe.h>
#include <botan/pk_keys.h>

namespace Botan {

/*************************************************
* X.509 Public Key                               *
*************************************************/
class X509_PublicKey : public virtual PK_Key
   {
   public:
      u64bit key_id() const;
      virtual MemoryVector<byte> DER_encode_pub() const = 0;
      virtual MemoryVector<byte> DER_encode_params() const = 0;
      virtual void BER_decode_pub(DataSource&) = 0;
      virtual void BER_decode_params(DataSource&) = 0;
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
