/*
* CRL Entry
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/crl_ent.h>
#include <botan/x509_ext.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/oids.h>
#include <botan/util.h>

namespace Botan {

/*
* Create a CRL_Entry
*/
CRL_Entry::CRL_Entry(bool t_on_unknown_crit) :
   throw_on_unknown_critical(t_on_unknown_crit)
   {
   reason = UNSPECIFIED;
   }

/*
* Create a CRL_Entry
*/
CRL_Entry::CRL_Entry(const X509_Certificate& cert, CRL_Code why) :
   throw_on_unknown_critical(false)
   {
   serial = cert.serial_number();
   time = X509_Time(system_time());
   reason = why;
   }

/*
* Compare two CRL_Entrys for equality
*/
bool operator==(const CRL_Entry& a1, const CRL_Entry& a2)
   {
   return (a1.serial_number() == a2.serial_number() &&
           a1.expire_time() == a2.expire_time() &&
           a1.reason_code() == a2.reason_code());
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

   extensions.add(new Cert_Extension::CRL_ReasonCode(reason));

   der.start_cons(SEQUENCE)
         .encode(BigInt::decode(serial, serial.size()))
         .encode(time)
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
   reason = UNSPECIFIED;

   BER_Decoder entry = source.start_cons(SEQUENCE);

   entry.decode(serial_number_bn).decode(time);

   if(entry.more_items())
      {
      Extensions extensions(throw_on_unknown_critical);
      entry.decode(extensions);
      Data_Store info;
      extensions.contents_to(info, info);
      reason = CRL_Code(info.get1_u32bit("X509v3.CRLReasonCode"));
      }

   entry.end_cons();

   serial = BigInt::encode(serial_number_bn);
   }

}
