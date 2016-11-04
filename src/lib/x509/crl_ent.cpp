/*
* CRL Entry
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/crl_ent.h>
#include <botan/x509cert.h>
#include <botan/x509_ext.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/oids.h>

namespace Botan {

/*
* Create a CRL_Entry
*/
CRL_Entry::CRL_Entry(bool t_on_unknown_crit) :
   m_throw_on_unknown_critical(t_on_unknown_crit)
   {
   m_reason = UNSPECIFIED;
   }

/*
* Create a CRL_Entry
*/
CRL_Entry::CRL_Entry(const X509_Certificate& cert, CRL_Code why) :
   m_throw_on_unknown_critical(false)
   {
   m_serial = cert.serial_number();
   m_time = X509_Time(std::chrono::system_clock::now());
   m_reason = why;
   }

/*
* Compare two CRL_Entrys for equality
*/
bool operator==(const CRL_Entry& a1, const CRL_Entry& a2)
   {
   if(a1.serial_number() != a2.serial_number())
      return false;
   if(a1.expire_time() != a2.expire_time())
      return false;
   if(a1.reason_code() != a2.reason_code())
      return false;
   return true;
   }

/*
* Compare two CRL_Entrys for inequality
*/
bool operator!=(const CRL_Entry& a1, const CRL_Entry& a2)
   {
   return !(a1 == a2);
   }

/*
* DER encode a CRL_Entry
*/
void CRL_Entry::encode_into(DER_Encoder& der) const
   {
   Extensions extensions;

   extensions.add(new Cert_Extension::CRL_ReasonCode(m_reason));

   der.start_cons(SEQUENCE)
      .encode(BigInt::decode(m_serial))
         .encode(m_time)
         .start_cons(SEQUENCE)
            .encode(extensions)
          .end_cons()
      .end_cons();
   }

/*
* Decode a BER encoded CRL_Entry
*/
void CRL_Entry::decode_from(BER_Decoder& source)
   {
   BigInt serial_number_bn;
   m_reason = UNSPECIFIED;

   BER_Decoder entry = source.start_cons(SEQUENCE);

   entry.decode(serial_number_bn).decode(m_time);

   if(entry.more_items())
      {
      Extensions extensions(m_throw_on_unknown_critical);
      entry.decode(extensions);
      Data_Store info;
      extensions.contents_to(info, info);
      m_reason = CRL_Code(info.get1_u32bit("X509v3.CRLReasonCode"));
      }

   entry.end_cons();

   m_serial = BigInt::encode(serial_number_bn);
   }

}
