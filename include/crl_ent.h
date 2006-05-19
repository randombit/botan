/*************************************************
* CRL Entry Header File                          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_CRL_ENTRY_H__
#define BOTAN_CRL_ENTRY_H__

#include <botan/x509cert.h>

namespace Botan {

/*************************************************
* CRL Entry                                      *
*************************************************/
class CRL_Entry : public ASN1_Object
   {
   public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);

      MemoryVector<byte> serial;
      X509_Time time;
      CRL_Code reason;
      CRL_Entry();
      CRL_Entry(const X509_Certificate&, CRL_Code = UNSPECIFIED);
   };

/*************************************************
* Comparison Operations                          *
*************************************************/
bool operator==(const CRL_Entry&, const CRL_Entry&);
bool operator!=(const CRL_Entry&, const CRL_Entry&);
bool operator<(const CRL_Entry&, const CRL_Entry&);

}

#endif
