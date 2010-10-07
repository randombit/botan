/*
* CRL Entry
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CRL_ENTRY_H__
#define BOTAN_CRL_ENTRY_H__

#include <botan/x509cert.h>

namespace Botan {

/**
* This class represents CRL entries
*/
class BOTAN_DLL CRL_Entry : public ASN1_Object
   {
   public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);

      /**
      * Get the serial number of the certificate associated with this entry.
      * @return the certificate's serial number
      */
      MemoryVector<byte> serial_number() const { return serial; }

      /**
      * Get the revocation date of the certificate associated with this entry
      * @return the certificate's revocation date
      */
      X509_Time expire_time() const { return time; }

      /**
      * Get the entries reason code
      * @return the reason code
      */
      CRL_Code reason_code() const { return reason; }

      /**
      * Construct an empty CRL entry.
      */
      CRL_Entry(bool throw_on_unknown_critical_extension = false);

      /**
      * Construct an CRL entry.
      * @param cert the certificate to revoke
      * @param reason the reason code to set in the entry
      */
      CRL_Entry(const X509_Certificate&, CRL_Code = UNSPECIFIED);

   private:
      bool throw_on_unknown_critical;
      MemoryVector<byte> serial;
      X509_Time time;
      CRL_Code reason;
   };

/**
* Test two CRL entries for equality in all fields.
*/
BOTAN_DLL bool operator==(const CRL_Entry&, const CRL_Entry&);

/**
* Test two CRL entries for inequality in at least one field.
*/
BOTAN_DLL bool operator!=(const CRL_Entry&, const CRL_Entry&);

}

#endif
