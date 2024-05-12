/*
* OCSP subtypes
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ocsp.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/x509_ext.h>

namespace Botan::OCSP {

CertID::CertID(const X509_Certificate& issuer, const BigInt& subject_serial) {
   /*
   In practice it seems some responders, including, notably,
   ocsp.verisign.com, will reject anything but SHA-1 here
   */
   auto hash = HashFunction::create_or_throw("SHA-1");

   m_hash_id = AlgorithmIdentifier(hash->name(), AlgorithmIdentifier::USE_NULL_PARAM);
   m_issuer_key_hash = unlock(hash->process(issuer.subject_public_key_bitstring()));
   m_issuer_dn_hash = unlock(hash->process(issuer.raw_subject_dn()));
   m_subject_serial = subject_serial;
}

bool CertID::is_id_for(const X509_Certificate& issuer, const X509_Certificate& subject) const {
   try {
      if(BigInt::from_bytes(subject.serial_number()) != m_subject_serial) {
         return false;
      }

      const std::string hash_algo = m_hash_id.oid().to_formatted_string();
      auto hash = HashFunction::create_or_throw(hash_algo);

      if(m_issuer_dn_hash != unlock(hash->process(subject.raw_issuer_dn()))) {
         return false;
      }

      if(m_issuer_key_hash != unlock(hash->process(issuer.subject_public_key_bitstring()))) {
         return false;
      }
   } catch(...) {
      return false;
   }

   return true;
}

void CertID::encode_into(DER_Encoder& to) const {
   to.start_sequence()
      .encode(m_hash_id)
      .encode(m_issuer_dn_hash, ASN1_Type::OctetString)
      .encode(m_issuer_key_hash, ASN1_Type::OctetString)
      .encode(m_subject_serial)
      .end_cons();
}

void CertID::decode_from(BER_Decoder& from) {
   from.start_sequence()
      .decode(m_hash_id)
      .decode(m_issuer_dn_hash, ASN1_Type::OctetString)
      .decode(m_issuer_key_hash, ASN1_Type::OctetString)
      .decode(m_subject_serial)
      .end_cons();
}

void SingleResponse::encode_into(DER_Encoder& /*to*/) const {
   throw Not_Implemented("SingleResponse::encode_into");
}

void SingleResponse::decode_from(BER_Decoder& from) {
   BER_Object cert_status;
   Extensions extensions;

   from.start_sequence()
      .decode(m_certid)
      .get_next(cert_status)
      .decode(m_thisupdate)
      .decode_optional(m_nextupdate, ASN1_Type(0), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)
      .decode_optional(extensions, ASN1_Type(1), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)
      .end_cons();

   /* CertStatus ::= CHOICE {
       good        [0]     IMPLICIT NULL,
       revoked     [1]     IMPLICIT RevokedInfo,
       unknown     [2]     IMPLICIT UnknownInfo }

   RevokedInfo ::= SEQUENCE {
       revocationTime              GeneralizedTime,
       revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }

   UnknownInfo ::= NULL

   We should verify the expected body and decode the RevokedInfo
   */
   m_cert_status = static_cast<uint32_t>(cert_status.type());
}

}  // namespace Botan::OCSP
