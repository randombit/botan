/*
* OCSP subtypes
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ocsp.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/x509_ext.h>
#include <botan/hash.h>

namespace Botan {

namespace OCSP {

CertID::CertID(const X509_Certificate& issuer,
               const BigInt& subject_serial)
   {
   /*
   In practice it seems some responders, including, notably,
   ocsp.verisign.com, will reject anything but SHA-1 here
   */
   std::unique_ptr<HashFunction> hash(HashFunction::create_or_throw("SHA-160"));

   m_hash_id = AlgorithmIdentifier(hash->name(), AlgorithmIdentifier::USE_NULL_PARAM);
   m_issuer_key_hash = unlock(hash->process(issuer.subject_public_key_bitstring()));
   m_issuer_dn_hash = unlock(hash->process(issuer.raw_subject_dn()));
   m_subject_serial = subject_serial;
   }

bool CertID::is_id_for(const X509_Certificate& issuer,
                       const X509_Certificate& subject) const
   {
   try
      {
      if(BigInt::decode(subject.serial_number()) != m_subject_serial)
         return false;

      const std::string hash_algo = m_hash_id.get_oid().to_formatted_string();
      std::unique_ptr<HashFunction> hash = HashFunction::create_or_throw(hash_algo);

      if(m_issuer_dn_hash != unlock(hash->process(subject.raw_issuer_dn())))
         return false;

      if(m_issuer_key_hash != unlock(hash->process(issuer.subject_public_key_bitstring())))
         return false;
      }
   catch(...)
      {
      return false;
      }

   return true;
   }

void CertID::encode_into(class DER_Encoder& to) const
   {
   to.start_cons(SEQUENCE)
      .encode(m_hash_id)
      .encode(m_issuer_dn_hash, OCTET_STRING)
      .encode(m_issuer_key_hash, OCTET_STRING)
      .encode(m_subject_serial)
      .end_cons();
   }

void CertID::decode_from(class BER_Decoder& from)
   {
   from.start_cons(SEQUENCE)
      .decode(m_hash_id)
      .decode(m_issuer_dn_hash, OCTET_STRING)
      .decode(m_issuer_key_hash, OCTET_STRING)
      .decode(m_subject_serial)
      .end_cons();

   }

void SingleResponse::encode_into(class DER_Encoder&) const
   {
   throw Not_Implemented("SingleResponse::encode_into");
   }

void SingleResponse::decode_from(class BER_Decoder& from)
   {
   BER_Object cert_status;
   Extensions extensions;

   from.start_cons(SEQUENCE)
      .decode(m_certid)
      .get_next(cert_status)
      .decode(m_thisupdate)
      .decode_optional(m_nextupdate, ASN1_Tag(0),
                       ASN1_Tag(CONTEXT_SPECIFIC | CONSTRUCTED))
      .decode_optional(extensions,
                       ASN1_Tag(1),
                       ASN1_Tag(CONTEXT_SPECIFIC | CONSTRUCTED))
      .end_cons();

   m_cert_status = cert_status.type();
   }

}

}
