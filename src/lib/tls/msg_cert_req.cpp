/*
* Certificate Request Message
* (C) 2004-2006,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

namespace TLS {

namespace {

std::string cert_type_code_to_name(uint8_t code)
   {
   switch(code)
      {
      case 1:
         return "RSA";
      case 2:
         return "DSA";
      case 64:
         return "ECDSA";
      default:
         return ""; // DH or something else
      }
   }

uint8_t cert_type_name_to_code(const std::string& name)
   {
   if(name == "RSA")
      return 1;
   if(name == "DSA")
      return 2;
   if(name == "ECDSA")
      return 64;

   throw Invalid_Argument("Unknown cert type " + name);
   }

}

/**
* Create a new Certificate Request message
*/
Certificate_Req::Certificate_Req(Handshake_IO& io,
                                 Handshake_Hash& hash,
                                 const Policy& policy,
                                 const std::vector<X509_DN>& ca_certs,
                                 Protocol_Version version) :
   m_names(ca_certs),
   m_cert_key_types({ "RSA", "ECDSA", "DSA" })
   {
   if(version.supports_negotiable_signature_algorithms())
      {
      m_schemes = policy.allowed_signature_schemes();
      }

   hash.update(io.send(*this));
   }

/**
* Deserialize a Certificate Request message
*/
Certificate_Req::Certificate_Req(const std::vector<uint8_t>& buf,
                                 Protocol_Version version)
   {
   if(buf.size() < 4)
      throw Decoding_Error("Certificate_Req: Bad certificate request");

   TLS_Data_Reader reader("CertificateRequest", buf);

   std::vector<uint8_t> cert_type_codes = reader.get_range_vector<uint8_t>(1, 1, 255);

   for(size_t i = 0; i != cert_type_codes.size(); ++i)
      {
      const std::string cert_type_name = cert_type_code_to_name(cert_type_codes[i]);

      if(cert_type_name.empty()) // something we don't know
         continue;

      m_cert_key_types.emplace_back(cert_type_name);
      }

   if(version.supports_negotiable_signature_algorithms())
      {
      const std::vector<uint8_t> algs = reader.get_range_vector<uint8_t>(2, 2, 65534);

      if(algs.size() % 2 != 0)
         throw Decoding_Error("Bad length for signature IDs in certificate request");

      for(size_t i = 0; i != algs.size(); i += 2)
         {
         m_schemes.push_back(static_cast<Signature_Scheme>(make_uint16(algs[i], algs[i+1])));
         }
      }

   const uint16_t purported_size = reader.get_uint16_t();

   if(reader.remaining_bytes() != purported_size)
      throw Decoding_Error("Inconsistent length in certificate request");

   while(reader.has_remaining())
      {
      std::vector<uint8_t> name_bits = reader.get_range_vector<uint8_t>(2, 0, 65535);

      BER_Decoder decoder(name_bits.data(), name_bits.size());
      X509_DN name;
      decoder.decode(name);
      m_names.emplace_back(name);
      }
   }

/**
* Serialize a Certificate Request message
*/
std::vector<uint8_t> Certificate_Req::serialize() const
   {
   std::vector<uint8_t> buf;

   std::vector<uint8_t> cert_types;

   for(size_t i = 0; i != m_cert_key_types.size(); ++i)
      cert_types.push_back(cert_type_name_to_code(m_cert_key_types[i]));

   append_tls_length_value(buf, cert_types, 1);

   if(m_schemes.size() > 0)
      buf += Signature_Algorithms(m_schemes).serialize(Connection_Side::SERVER);

   std::vector<uint8_t> encoded_names;

   for(size_t i = 0; i != m_names.size(); ++i)
      {
      DER_Encoder encoder;
      encoder.encode(m_names[i]);

      append_tls_length_value(encoded_names, encoder.get_contents(), 2);
      }

   append_tls_length_value(buf, encoded_names, 2);

   return buf;
   }

}

}
