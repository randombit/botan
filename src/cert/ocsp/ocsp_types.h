/*
* OCSP subtypes
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_OCSP_TYPES_H__
#define BOTAN_OCSP_TYPES_H__

#include <botan/x509cert.h>
#include <botan/asn1_time.h>
#include <botan/bigint.h>

namespace Botan {

namespace OCSP {

class BOTAN_DLL CertID : public ASN1_Object
   {
   public:
      CertID() {}

      CertID(const X509_Certificate& issuer,
             const X509_Certificate& subject);

      bool is_id_for(const X509_Certificate& issuer,
                     const X509_Certificate& subject) const;

      void encode_into(class DER_Encoder& to) const override;

      void decode_from(class BER_Decoder& from) override;
   private:
      std::vector<byte> extract_key_bitstr(const X509_Certificate& cert) const;

      AlgorithmIdentifier m_hash_id;
      std::vector<byte> m_issuer_dn_hash;
      std::vector<byte> m_issuer_key_hash;
      BigInt m_subject_serial;
   };

class BOTAN_DLL SingleResponse : public ASN1_Object
   {
   public:
      SingleResponse() : m_good_status(false) {}

      /**
      * Return true if and only if this response is one matching
      * the current issuer and subject AND is a postive affirmation
      */
      bool affirmative_response_for(const X509_Certificate& issuer,
                                    const X509_Certificate& subject) const;

      void encode_into(class DER_Encoder& to) const override;

      void decode_from(class BER_Decoder& from) override;
   private:
      CertID m_certid;
      bool m_good_status;
      X509_Time m_thisupdate;
      X509_Time m_nextupdate;
   };

}

}

#endif
