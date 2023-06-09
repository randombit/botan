/*
* Certificate Request Message
* (C) 2004-2006,2012 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/tls_extensions.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

Handshake_Type Certificate_Request_12::type() const {
   return Handshake_Type::CertificateRequest;
}

namespace {

std::string cert_type_code_to_name(uint8_t code) {
   switch(code) {
      case 1:
         return "RSA";
      case 64:
         return "ECDSA";
      default:
         return "";  // DH or something else
   }
}

uint8_t cert_type_name_to_code(std::string_view name) {
   if(name == "RSA") {
      return 1;
   }
   if(name == "ECDSA") {
      return 64;
   }

   throw Invalid_Argument(fmt("Unknown/unhandled TLS cert type {}", name));
}

}  // namespace

/**
* Create a new Certificate Request message
*/
Certificate_Request_12::Certificate_Request_12(Handshake_IO& io,
                                               Handshake_Hash& hash,
                                               const Policy& policy,
                                               const std::vector<X509_DN>& ca_certs) :
      m_names(ca_certs), m_cert_key_types({"RSA", "ECDSA"}) {
   m_schemes = policy.acceptable_signature_schemes();
   hash.update(io.send(*this));
}

/**
* Deserialize a Certificate Request message
*/
Certificate_Request_12::Certificate_Request_12(const std::vector<uint8_t>& buf) {
   if(buf.size() < 4) {
      throw Decoding_Error("Certificate_Req: Bad certificate request");
   }

   TLS_Data_Reader reader("CertificateRequest", buf);

   const auto cert_type_codes = reader.get_range_vector<uint8_t>(1, 1, 255);

   for(const auto cert_type_code : cert_type_codes) {
      const std::string cert_type_name = cert_type_code_to_name(cert_type_code);

      if(cert_type_name.empty()) {  // something we don't know
         continue;
      }

      m_cert_key_types.emplace_back(cert_type_name);
   }

   const std::vector<uint8_t> algs = reader.get_range_vector<uint8_t>(2, 2, 65534);

   if(algs.size() % 2 != 0) {
      throw Decoding_Error("Bad length for signature IDs in certificate request");
   }

   for(size_t i = 0; i != algs.size(); i += 2) {
      m_schemes.emplace_back(make_uint16(algs[i], algs[i + 1]));
   }

   const uint16_t purported_size = reader.get_uint16_t();

   if(reader.remaining_bytes() != purported_size) {
      throw Decoding_Error("Inconsistent length in certificate request");
   }

   while(reader.has_remaining()) {
      std::vector<uint8_t> name_bits = reader.get_range_vector<uint8_t>(2, 0, 65535);

      BER_Decoder decoder(name_bits.data(), name_bits.size());
      X509_DN name;
      decoder.decode(name);
      m_names.emplace_back(name);
   }
}

const std::vector<std::string>& Certificate_Request_12::acceptable_cert_types() const {
   return m_cert_key_types;
}

const std::vector<X509_DN>& Certificate_Request_12::acceptable_CAs() const {
   return m_names;
}

const std::vector<Signature_Scheme>& Certificate_Request_12::signature_schemes() const {
   return m_schemes;
}

/**
* Serialize a Certificate Request message
*/
std::vector<uint8_t> Certificate_Request_12::serialize() const {
   std::vector<uint8_t> buf;

   std::vector<uint8_t> cert_types;

   cert_types.reserve(m_cert_key_types.size());
   for(const auto& cert_key_type : m_cert_key_types) {
      cert_types.push_back(cert_type_name_to_code(cert_key_type));
   }

   append_tls_length_value(buf, cert_types, 1);

   if(!m_schemes.empty()) {
      buf += Signature_Algorithms(m_schemes).serialize(Connection_Side::Server);
   }

   std::vector<uint8_t> encoded_names;

   for(const auto& name : m_names) {
      DER_Encoder encoder;
      encoder.encode(name);

      append_tls_length_value(encoded_names, encoder.get_contents(), 2);
   }

   append_tls_length_value(buf, encoded_names, 2);

   return buf;
}
}  // namespace Botan::TLS
