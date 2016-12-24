/*
* Certificate Verify Message
* (C) 2004,2006,2011,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_state.h>

namespace Botan {

namespace TLS {

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
      state.choose_sig_format(*priv_key, m_hash_algo, m_sig_algo, true, policy);

   PK_Signer signer(*priv_key, rng, format.first, format.second);

   m_signature = signer.sign_message(state.hash().get_contents(), rng);

   state.hash().update(io.send(*this));
   }

/*
* Deserialize a Certificate Verify message
*/
Certificate_Verify::Certificate_Verify(const std::vector<uint8_t>& buf,
                                       Protocol_Version version)
   {
   TLS_Data_Reader reader("CertificateVerify", buf);

   if(version.supports_negotiable_signature_algorithms())
      {
      m_hash_algo = Signature_Algorithms::hash_algo_name(reader.get_byte());
      m_sig_algo = Signature_Algorithms::sig_algo_name(reader.get_byte());
      }

   m_signature = reader.get_range<uint8_t>(2, 0, 65535);
   }

/*
* Serialize a Certificate Verify message
*/
std::vector<uint8_t> Certificate_Verify::serialize() const
   {
   std::vector<uint8_t> buf;

   if(!m_hash_algo.empty() && !m_sig_algo.empty())
      {
      buf.push_back(Signature_Algorithms::hash_algo_code(m_hash_algo));
      buf.push_back(Signature_Algorithms::sig_algo_code(m_sig_algo));
      }

   const uint16_t sig_len = static_cast<uint16_t>(m_signature.size());
   buf.push_back(get_byte(0, sig_len));
   buf.push_back(get_byte(1, sig_len));
   buf += m_signature;

   return buf;
   }

/*
* Verify a Certificate Verify message
*/
bool Certificate_Verify::verify(const X509_Certificate& cert,
                                const Handshake_State& state,
                                const Policy& policy) const
   {
   std::unique_ptr<Public_Key> key(cert.subject_public_key());

   policy.check_peer_key_acceptable(*key);

   std::pair<std::string, Signature_Format> format =
      state.parse_sig_format(*key.get(), m_hash_algo, m_sig_algo,
                             true, policy);

   PK_Verifier verifier(*key, format.first, format.second);

   const bool signature_valid =
      verifier.verify_message(state.hash().get_contents(), m_signature);

#if defined(BOTAN_UNSAFE_FUZZER_MODE)
   return true;
#else
   return signature_valid;
#endif
   }

}

}
