/*
* TLS Session State
* (C) 2011-2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_session.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/asn1_str.h>
#include <botan/pem.h>
#include <botan/time.h>
#include <botan/lookup.h>
#include <memory>

namespace Botan {

namespace TLS {

Session::Session(const MemoryRegion<byte>& session_identifier,
                 const MemoryRegion<byte>& master_secret,
                 Protocol_Version version,
                 u16bit ciphersuite,
                 byte compression_method,
                 Connection_Side side,
                 bool secure_renegotiation_supported,
                 size_t fragment_size,
                 const std::vector<X509_Certificate>& certs,
                 const std::string& sni_hostname,
                 const std::string& srp_identifier) :
   m_start_time(system_time()),
   m_identifier(session_identifier),
   m_master_secret(master_secret),
   m_version(version),
   m_ciphersuite(ciphersuite),
   m_compression_method(compression_method),
   m_connection_side(side),
   m_secure_renegotiation_supported(secure_renegotiation_supported),
   m_fragment_size(fragment_size),
   m_peer_certs(certs),
   m_sni_hostname(sni_hostname),
   m_srp_identifier(srp_identifier)
   {
   }

Session::Session(const byte ber[], size_t ber_len)
   {
   BER_Decoder decoder(ber, ber_len);

   byte side_code = 0;
   ASN1_String sni_hostname_str;
   ASN1_String srp_identifier_str;

   byte major_version = 0, minor_version = 0;

   MemoryVector<byte> peer_cert_bits;

   BER_Decoder(ber, ber_len)
      .start_cons(SEQUENCE)
        .decode_and_check(static_cast<size_t>(TLS_SESSION_PARAM_STRUCT_VERSION),
                          "Unknown version in session structure")
        .decode(m_identifier, OCTET_STRING)
        .decode_integer_type(m_start_time)
        .decode_integer_type(major_version)
        .decode_integer_type(minor_version)
        .decode_integer_type(m_ciphersuite)
        .decode_integer_type(m_compression_method)
        .decode_integer_type(side_code)
        .decode_integer_type(m_fragment_size)
        .decode(m_secure_renegotiation_supported)
        .decode(m_master_secret, OCTET_STRING)
        .decode(peer_cert_bits, OCTET_STRING)
        .decode(sni_hostname_str)
        .decode(srp_identifier_str)
      .end_cons()
      .verify_end();

   m_version = Protocol_Version(major_version, minor_version);
   m_sni_hostname = sni_hostname_str.value();
   m_srp_identifier = srp_identifier_str.value();
   m_connection_side = static_cast<Connection_Side>(side_code);

   if(!peer_cert_bits.empty())
      {
      DataSource_Memory certs(peer_cert_bits);

      while(!certs.end_of_data())
         m_peer_certs.push_back(X509_Certificate(certs));
      }
   }

Session::Session(const std::string& pem)
   {
   SecureVector<byte> der = PEM_Code::decode_check_label(pem, "SSL SESSION");

   *this = Session(&der[0], der.size());
   }

SecureVector<byte> Session::DER_encode() const
   {
   MemoryVector<byte> peer_cert_bits;
   for(size_t i = 0; i != m_peer_certs.size(); ++i)
      peer_cert_bits += m_peer_certs[i].BER_encode();

   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode(static_cast<size_t>(TLS_SESSION_PARAM_STRUCT_VERSION))
         .encode(m_identifier, OCTET_STRING)
         .encode(static_cast<size_t>(m_start_time))
         .encode(static_cast<size_t>(m_version.major_version()))
         .encode(static_cast<size_t>(m_version.minor_version()))
         .encode(static_cast<size_t>(m_ciphersuite))
         .encode(static_cast<size_t>(m_compression_method))
         .encode(static_cast<size_t>(m_connection_side))
         .encode(static_cast<size_t>(m_fragment_size))
         .encode(m_secure_renegotiation_supported)
         .encode(m_master_secret, OCTET_STRING)
         .encode(peer_cert_bits, OCTET_STRING)
         .encode(ASN1_String(m_sni_hostname, UTF8_STRING))
         .encode(ASN1_String(m_srp_identifier, UTF8_STRING))
      .end_cons()
   .get_contents();
   }

std::string Session::PEM_encode() const
   {
   return PEM_Code::encode(this->DER_encode(), "SSL SESSION");
   }

MemoryVector<byte>
Session::encrypt(const SymmetricKey& master_key,
                 const MemoryRegion<byte>& key_name,
                 RandomNumberGenerator& rng)
   {
   if(key_name.size() != 16)
      throw Encoding_Error("Bad length " + to_string(key_name.size()) +
                           " for key_name in TLS_Session::encrypt");

   if(master_key.length() == 0)
      throw Decoding_Error("Session master_key not set");

   std::auto_ptr<KDF> kdf(get_kdf("KDF2(SHA-256)"));

   SymmetricKey aes_key = kdf->derive_key(32, master_key.bits_of(),
                                          "session-ticket.cipher-key");

   SymmetricKey hmac_key = kdf->derive_key(32, master_key.bits_of(),
                                           "session-ticket.hmac-key");

   InitializationVector aes_iv(rng, 16);

   std::auto_ptr<MessageAuthenticationCode> mac(get_mac("HMAC(SHA-256)"));
   mac->set_key(hmac_key);

   Pipe pipe(get_cipher("AES-256/CBC", aes_key, aes_iv, ENCRYPTION));
   pipe.process_msg(this->DER_encode());
   MemoryVector<byte> ctext = pipe.read_all(0);

   MemoryVector<byte> out;
   out += key_name;
   out += aes_iv.bits_of();
   out += ctext;

   mac->update(out);

   out += mac->final();
   return out;
   }

Session Session::decrypt(const MemoryRegion<byte>& buf,
                         const SymmetricKey& master_key,
                         const MemoryRegion<byte>& key_name)
   {
   try
      {
      if(buf.size() < (16 + 16 + 32 + 1))
         throw Decoding_Error("Encrypted TLS_Session too short to be real");

      if(master_key.length() == 0)
         throw Decoding_Error("Session master_key not set");

      if(key_name.size() != 16)
         throw Decoding_Error("Bad length " + to_string(key_name.size()) +
                              " for key_name");

      std::auto_ptr<KDF> kdf(get_kdf("KDF2(SHA-256)"));

      SymmetricKey hmac_key = kdf->derive_key(32, master_key.bits_of(),
                                              "session-ticket.hmac-key");

      std::auto_ptr<MessageAuthenticationCode> mac(get_mac("HMAC(SHA-256)"));
      mac->set_key(hmac_key);

      mac->update(&buf[0], buf.size() - 32);
      MemoryVector<byte> computed_mac = mac->final();

      if(!same_mem(&buf[buf.size() - 32], &computed_mac[0], computed_mac.size()))
         throw Decoding_Error("MAC verification failed");

      SymmetricKey aes_key = kdf->derive_key(32, master_key.bits_of(),
                                             "session-ticket.cipher-key");

      InitializationVector aes_iv(&buf[16], 16);

      Pipe pipe(get_cipher("AES-256/CBC", aes_key, aes_iv, DECRYPTION));
      pipe.process_msg(&buf[16], buf.size() - (16 + 32));
      MemoryVector<byte> ber = pipe.read_all();

      return Session(&ber[0], ber.size());
      }
   catch(...)
      {
      throw Decoding_Error("Failed to decrypt encrypted session");
      }
   }

}

}

