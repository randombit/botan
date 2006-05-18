/*************************************************
* CRL Entry Source File                          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/crl_ent.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/conf.h>
#include <botan/oids.h>
#include <botan/x509_crl.h>
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

namespace DER {

/*************************************************
* DER encode an CRL_Entry                        *
*************************************************/
void encode(DER_Encoder& der, const CRL_Entry& crl_ent)
   {
   der.start_sequence()
      .encode(BigInt::decode(crl_ent.serial, crl_ent.serial.size()))
      .encode(crl_ent.time)
      .start_sequence();

   if(crl_ent.reason != UNSPECIFIED)
      {
#if 1
      der.start_sequence()
         .encode(OIDS::lookup("X509v3.ReasonCode"))
         .encode(
            DER_Encoder()
               .encode((u32bit)crl_ent.reason, ENUMERATED, UNIVERSAL)
            .get_contents(),
            OCTET_STRING)
         .end_sequence();
#else
      DER_Encoder v2_ext;
      v2_ext.encode((u32bit)crl_ent.reason, ENUMERATED, UNIVERSAL);
      der.encode(Extension("X509v3.ReasonCode", v2_ext.get_contents()));
#endif
      }

   der.end_sequence()
      .end_sequence();
   }

}

namespace BER {

namespace {

/*************************************************
* Decode a CRL entry extension                   *
*************************************************/
void handle_crl_entry_extension(CRL_Entry& crl_ent, const Extension& extn)
   {
   BER_Decoder value(extn.value);

   if(extn.oid == OIDS::lookup("X509v3.ReasonCode"))
      {
      u32bit reason_code;
      value.decode(reason_code, ENUMERATED, UNIVERSAL);
      crl_ent.reason = CRL_Code(reason_code);
      }
   else
      {
      if(extn.critical)
         {
         std::string action = Config::get_string("x509/crl/unknown_critical");
         if(action == "throw")
            throw Decoding_Error("Unknown critical CRL entry extension " +
                                 extn.oid.as_string());
         else if(action != "ignore")
            throw Invalid_Argument("Bad value of x509/crl/unknown_critical: "
                                   + action);
         }
      return;
      }

   value.verify_end();
   }

}

/*************************************************
* Decode a BER encoded CRL_Entry                 *
*************************************************/
void decode(BER_Decoder& source, CRL_Entry& crl_ent)
   {
   BigInt serial_number;

   BER_Decoder sequence = BER::get_subsequence(source);
   sequence.decode(serial_number);
   crl_ent.serial = BigInt::encode(serial_number);
   BER::decode(sequence, crl_ent.time);

   if(sequence.more_items())
      {
      BER_Decoder crl_entry_exts = BER::get_subsequence(sequence);
      while(crl_entry_exts.more_items())
         {
         Extension extn;
         BER::decode(crl_entry_exts, extn);
         handle_crl_entry_extension(crl_ent, extn);
         }
      }

   sequence.verify_end();
   }

}

}
