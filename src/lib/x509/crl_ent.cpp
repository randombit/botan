/*
* CRL Entry
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_crl.h>

#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/der_enc.h>
#include <botan/x509_ext.h>
#include <botan/x509cert.h>

namespace Botan {

struct CRL_Entry_Data {
      std::vector<uint8_t> m_serial;
      X509_Time m_time;
      CRL_Code m_reason = CRL_Code::Unspecified;
      Extensions m_extensions;
};

/*
* Create a CRL_Entry
*/
CRL_Entry::CRL_Entry(const X509_Certificate& cert, CRL_Code why) {
   m_data = std::make_shared<CRL_Entry_Data>();
   m_data->m_serial = cert.serial_number();
   m_data->m_time = X509_Time(std::chrono::system_clock::now());
   m_data->m_reason = why;

   if(why != CRL_Code::Unspecified) {
      m_data->m_extensions.add(std::make_unique<Cert_Extension::CRL_ReasonCode>(why));
   }
}

/*
* Compare two CRL_Entrys for equality
*/
bool operator==(const CRL_Entry& a1, const CRL_Entry& a2) {
   if(a1.serial_number() != a2.serial_number()) {
      return false;
   }
   if(a1.expire_time() != a2.expire_time()) {
      return false;
   }
   if(a1.reason_code() != a2.reason_code()) {
      return false;
   }
   return true;
}

/*
* Compare two CRL_Entrys for inequality
*/
bool operator!=(const CRL_Entry& a1, const CRL_Entry& a2) {
   return !(a1 == a2);
}

/*
* DER encode a CRL_Entry
*/
void CRL_Entry::encode_into(DER_Encoder& der) const {
   der.start_sequence()
      .encode(BigInt::from_bytes(serial_number()))
      .encode(expire_time())
      .start_sequence()
      .encode(extensions())
      .end_cons()
      .end_cons();
}

namespace {

std::vector<uint8_t> decode_serial_number(const BER_Object& obj) {
   obj.assert_is_a(ASN1_Type::Integer, ASN1_Class::Universal);

   if(!obj.data().empty() && obj.data()[0] == 0x00) {
      return std::vector<uint8_t>(obj.data().begin() + 1, obj.data().end());
   } else if(!obj.data().empty() && obj.data()[0] & 0x80) {
      std::vector<uint8_t> vec(obj.data().begin(), obj.data().end());
      for(size_t i = vec.size(); i > 0; --i) {
         if(vec[i - 1]--) {
            break;
         }
      }
      for(size_t i = 0; i != vec.size(); ++i) {
         vec[i] = ~vec[i];
      }

      return vec;
   } else {
      return std::vector<uint8_t>(obj.data().begin(), obj.data().end());
   }
}

}  // namespace

/*
* Decode a BER encoded CRL_Entry
*/
void CRL_Entry::decode_from(BER_Decoder& source) {
   auto data = std::make_unique<CRL_Entry_Data>();

   BER_Decoder entry = source.start_sequence();

   data->m_serial = decode_serial_number(entry.get_next_object());

   entry.decode(data->m_time);

   if(entry.more_items()) {
      entry.decode(data->m_extensions);
      if(auto ext = data->m_extensions.get_extension_object_as<Cert_Extension::CRL_ReasonCode>()) {
         data->m_reason = ext->get_reason();
      } else {
         data->m_reason = CRL_Code::Unspecified;
      }
   }

   entry.end_cons();

   m_data = std::move(data);
}

const CRL_Entry_Data& CRL_Entry::data() const {
   if(!m_data) {
      throw Invalid_State("CRL_Entry_Data uninitialized");
   }

   return *m_data;
}

const std::vector<uint8_t>& CRL_Entry::serial_number() const {
   return data().m_serial;
}

const X509_Time& CRL_Entry::expire_time() const {
   return data().m_time;
}

CRL_Code CRL_Entry::reason_code() const {
   return data().m_reason;
}

const Extensions& CRL_Entry::extensions() const {
   return data().m_extensions;
}

}  // namespace Botan
