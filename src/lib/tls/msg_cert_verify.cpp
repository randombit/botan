/*
* Certificate Verify Message
* (C) 2004,2006,2011,2012 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>

#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

/*
* Deserialize a Certificate Verify message
*/
Certificate_Verify::Certificate_Verify(const std::vector<uint8_t>& buf) {
   TLS_Data_Reader reader("CertificateVerify", buf);

   m_scheme = Signature_Scheme(reader.get_uint16_t());
   m_signature = reader.get_range<uint8_t>(2, 0, 65535);
   reader.assert_done();

   if(!m_scheme.is_set()) {
      throw Decoding_Error("Counterparty did not send hash/sig IDS");
   }
}

/*
* Serialize a Certificate Verify message
*/
std::vector<uint8_t> Certificate_Verify::serialize() const {
   BOTAN_ASSERT_NOMSG(m_scheme.is_set());
   std::vector<uint8_t> buf;
   buf.reserve(2 + 2 + m_signature.size());  // work around GCC warning

   const auto code = m_scheme.wire_code();
   buf.push_back(get_byte<0>(code));
   buf.push_back(get_byte<1>(code));

   if(m_signature.size() > 0xFFFF) {
      throw Encoding_Error("Certificate_Verify signature too long to encode");
   }

   const uint16_t sig_len = static_cast<uint16_t>(m_signature.size());
   buf.push_back(get_byte<0>(sig_len));
   buf.push_back(get_byte<1>(sig_len));
   buf += m_signature;

   return buf;
}

}  // namespace Botan::TLS
