/*************************************************
* CRL Entry Header File                          *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_CRL_ENTRY_H__
#define BOTAN_CRL_ENTRY_H__

#include <botan/x509cert.h>

namespace Botan {

/*************************************************
* CRL Entry                                      *
*************************************************/
class BOTAN_DLL CRL_Entry : public ASN1_Object
   {
   public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);

      MemoryVector<byte> serial_number() const { return serial; }
      X509_Time expire_time() const { return time; }
      CRL_Code reason_code() const { return reason; }

      CRL_Entry();
      CRL_Entry(const X509_Certificate&, CRL_Code = UNSPECIFIED);

   private:
      MemoryVector<byte> serial;
      X509_Time time;
      CRL_Code reason;
   };

/*************************************************
* Comparison Operations                          *
*************************************************/
BOTAN_DLL bool operator==(const CRL_Entry&, const CRL_Entry&);
BOTAN_DLL bool operator!=(const CRL_Entry&, const CRL_Entry&);
BOTAN_DLL bool operator<(const CRL_Entry&, const CRL_Entry&);

}

#endif
