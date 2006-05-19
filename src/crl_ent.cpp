/*************************************************
* CRL Entry Source File                          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/crl_ent.h>
#include <botan/x509_ext.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/conf.h>
#include <botan/oids.h>
#include <botan/util.h>

namespace Botan {

/*************************************************
* Create a CRL_Entry                             *
*************************************************/
CRL_Entry::CRL_Entry()
   {
   reason = UNSPECIFIED;
   }

/*************************************************
* Create a CRL_Entry                             *
*************************************************/
CRL_Entry::CRL_Entry(const X509_Certificate& cert, CRL_Code why)
   {
   serial = cert.serial_number();
   time = X509_Time(system_time());
   reason = why;
   }

/*************************************************
* Compare two CRL_Entrys for equality            *
*************************************************/
bool operator==(const CRL_Entry& a1, const CRL_Entry& a2)
   {
   if(a1.serial != a2.serial)
      return false;
   if(a1.time != a2.time)
      return false;
   if(a1.reason != a2.reason)
      return false;
   return true;
   }

/*************************************************
* Compare two CRL_Entrys for inequality          *
*************************************************/
bool operator!=(const CRL_Entry& a1, const CRL_Entry& a2)
   {
   return !(a1 == a2);
   }

/*************************************************
* Compare two CRL_Entrys                         *
*************************************************/
bool operator<(const CRL_Entry& a1, const CRL_Entry& a2)
   {
   return (a1.time.cmp(a2.time) < 0);
   }

/*************************************************
* DER encode a CRL_Entry                         *
*************************************************/
void CRL_Entry::encode_into(DER_Encoder& der) const
   {
   Extensions extensions;

   extensions.add(new Cert_Extension::CRL_ReasonCode(reason));

   der.start_cons(SEQUENCE)
         .encode(BigInt::decode(serial, serial.size()))
         .encode(time)
         .encode(extensions)
      .end_cons();
   }

/*************************************************
* Decode a BER encoded CRL_Entry                 *
*************************************************/
void CRL_Entry::decode_from(BER_Decoder& source)
   {
   BigInt serial_number_bn;

   source.start_cons(SEQUENCE)
      .decode(serial_number_bn)
      .decode(time);

   if(source.more_items())
      {
      BER_Decoder crl_entry_exts = source.start_cons(SEQUENCE);
      while(crl_entry_exts.more_items())
         {
         Extension extn;
         crl_entry_exts.decode(extn);

         BER_Decoder value(extn.value);

         if(extn.oid == OIDS::lookup("X509v3.ReasonCode"))
            {
            u32bit reason_code;
            value.decode(reason_code, ENUMERATED, UNIVERSAL);
            reason = CRL_Code(reason_code);
            }
         else if(extn.critical)
            {
            std::string action =
               Config::get_string("x509/crl/unknown_critical");

            if(action == "throw")
               throw Decoding_Error("Unknown critical CRL entry extn " +
                                    extn.oid.as_string());
            else if(action != "ignore")
               throw Invalid_Argument("Bad setting x509/crl/unknown_critical: "
                                      + action);
            }
         value.verify_end();
         }
      source.end_cons();
      }

   serial = BigInt::encode(serial_number_bn);
   }

}
