/*
* Certificate Verify Message
* (C) 2004,2006,2011,2012 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_reader.h>
#include <botan/pk_keys.h>
#include <botan/tls_extensions.h>
#include <botan/tls_messages.h>

namespace Botan::TLS {

/*
* Create a new Certificate Verify message
*/
Certificate_Verify::Certificate_Verify(Handshake_IO& io,
                                       Handshake_State& state,
                                       const Policy& policy,
                                       RandomNumberGenerator& rng,
                                       const Private_Key* priv_key)
   {
   BOTAN_ASSERT_NONNULL(priv_key);

   std::pair<std::string, Signature_Format> format =
      state.choose_sig_format(*priv_key, m_scheme, true, policy);

   m_signature =
      state.callbacks().tls_sign_message(*priv_key, rng, format.first, format.second,
                                         state.hash().get_contents());

   state.hash().update(io.send(*this));
   }

/*
* Deserialize a Certificate Verify message
*/
Certificate_Verify::Certificate_Verify(const std::vector<uint8_t>& buf)
   {
   TLS_Data_Reader reader("CertificateVerify", buf);

   m_scheme = static_cast<Signature_Scheme>(reader.get_uint16_t());
   m_signature = reader.get_range<uint8_t>(2, 0, 65535);
   reader.assert_done();
   }

/*
* Serialize a Certificate Verify message
*/
std::vector<uint8_t> Certificate_Verify::serialize() const
   {
   std::vector<uint8_t> buf;

   if(m_scheme != Signature_Scheme::NONE)
      {
      const uint16_t scheme_code = static_cast<uint16_t>(m_scheme);
      buf.push_back(get_byte<0>(scheme_code));
      buf.push_back(get_byte<1>(scheme_code));
      }

   if(m_signature.size() > 0xFFFF)
      { throw Encoding_Error("Certificate_Verify signature too long to encode"); }

   const uint16_t sig_len = static_cast<uint16_t>(m_signature.size());
   buf.push_back(get_byte<0>(sig_len));
   buf.push_back(get_byte<1>(sig_len));
   buf += m_signature;

   return buf;
   }


bool Certificate_Verify_12::verify(const X509_Certificate& cert,
                                   const Handshake_State& state,
                                   const Policy& policy) const
   {
   std::unique_ptr<Public_Key> key(cert.subject_public_key());

   policy.check_peer_key_acceptable(*key);

   std::pair<std::string, Signature_Format> format =
      state.parse_sig_format(*key.get(), m_scheme, true, policy);

   const bool signature_valid =
      state.callbacks().tls_verify_message(*key, format.first, format.second,
                                           state.hash().get_contents(), m_signature);

#if defined(BOTAN_UNSAFE_FUZZER_MODE)
   BOTAN_UNUSED(signature_valid);
   return true;

#else
   return signature_valid;

#endif
   }

/*
* Verify a Certificate Verify message
*/
bool Certificate_Verify_13::verify(const X509_Certificate& cert,
                                   const Handshake_State& state,
                                   const Policy& policy,
                                   const Connection_Side side,
                                   const secure_vector<uint8_t>& transcript_hash) const
   {
   std::unique_ptr<Public_Key> key(cert.subject_public_key());

   policy.check_peer_key_acceptable(*key);

   // TODO: won't work for client auth
   std::pair<std::string, Signature_Format> format =
      state.parse_sig_format(*key.get(), m_scheme, false, policy);

   std::vector<uint8_t> msg(64, 0x20);
   msg.reserve(64 + 32 + 1 + transcript_hash.size());

   const std::string context_string = (side == Botan::TLS::Connection_Side::SERVER)
                                      ? "TLS 1.3, server CertificateVerify"
                                      : "TLS 1.3, client CertificateVerify";

   msg.insert(msg.end(), context_string.cbegin(), context_string.cend());
   msg.push_back(0x00);

   msg.insert(msg.end(), transcript_hash.cbegin(), transcript_hash.cend());

   const bool signature_valid = state.callbacks().tls_verify_message(*key, format.first, format.second,
                                msg, m_signature);

#if defined(BOTAN_UNSAFE_FUZZER_MODE)
   BOTAN_UNUSED(signature_valid);
   return true;
#else
   return signature_valid;
#endif
   }

}
