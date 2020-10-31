/*
* CRL Entry
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_crl.h>
#include <botan/x509cert.h>
#include <botan/x509_ext.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/bigint.h>

namespace Botan {

struct CRL_Entry_Data
   {
   std::vector<uint8_t> m_serial;
   X509_Time m_time;
   CRL_Code m_reason = UNSPECIFIED;
   Extensions m_extensions;
   };

/*
* Create a CRL_Entry
*/
CRL_Entry::CRL_Entry(const X509_Certificate& cert, CRL_Code why)
   {
   m_data.reset(new CRL_Entry_Data);
   m_data->m_serial = cert.serial_number();
   m_data->m_time = X509_Time(std::chrono::system_clock::now());
   m_data->m_reason = why;

   if(why != UNSPECIFIED)
      {
      m_data->m_extensions.add(new Cert_Extension::CRL_ReasonCode(why));
      }
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
   der.start_cons(SEQUENCE)
      .encode(BigInt::decode(serial_number()))
      .encode(expire_time())
      .start_cons(SEQUENCE)
         .encode(extensions())
      .end_cons()
   .end_cons();
   }

/*
* Decode a BER encoded CRL_Entry
*/
void CRL_Entry::decode_from(BER_Decoder& source)
   {
   BigInt serial_number_bn;

   std::unique_ptr<CRL_Entry_Data> data(new CRL_Entry_Data);

   BER_Decoder entry = source.start_cons(SEQUENCE);

   entry.decode(serial_number_bn).decode(data->m_time);
   data->m_serial = BigInt::encode(serial_number_bn);

   if(entry.more_items())
      {
      entry.decode(data->m_extensions);
      if(auto ext = data->m_extensions.get_extension_object_as<Cert_Extension::CRL_ReasonCode>())
         {
         data->m_reason = ext->get_reason();
         }
      else
         {
         data->m_reason = UNSPECIFIED;
         }
      }

   entry.end_cons();

   m_data.reset(data.release());
   }

const CRL_Entry_Data& CRL_Entry::data() const
   {
   if(!m_data)
      {
      throw Invalid_State("CRL_Entry_Data uninitialized");
      }

   return *m_data.get();
   }

const std::vector<uint8_t>& CRL_Entry::serial_number() const
   {
   return data().m_serial;
   }

const X509_Time& CRL_Entry::expire_time() const
   {
   return data().m_time;
   }

CRL_Code CRL_Entry::reason_code() const
   {
   return data().m_reason;
   }

const Extensions& CRL_Entry::extensions() const
   {
   return data().m_extensions;
   }


}
