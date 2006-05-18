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
class CRL_Entry
   {
   public:
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

/*************************************************
* DER Encoding Functions                         *
*************************************************/
namespace DER {

void encode(DER_Encoder&, const CRL_Entry&);

}

/*************************************************
* BER Decoding Functions                         *
*************************************************/
namespace BER {

void decode(BER_Decoder&, CRL_Entry&);

}

}

#endif
