/*
* Certificate Request Message
* (C) 2004-2006,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_extensions.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/loadstor.h>
#include <botan/secqueue.h>

#include <stdio.h>

namespace Botan {

namespace TLS {

/**
* Create a new Certificate Request message
*/
Certificate_Req::Certificate_Req(Record_Writer& writer,
                                 Handshake_Hash& hash,
                                 const Policy& policy,
                                 const std::vector<X509_Certificate>& ca_certs,
                                 Version_Code version)
   {
   for(size_t i = 0; i != ca_certs.size(); ++i)
      names.push_back(ca_certs[i].subject_dn());

   cert_types.push_back(RSA_CERT);
   cert_types.push_back(DSS_CERT);

   if(version >= TLS_V12)
      {
      std::vector<std::string> hashes = policy.allowed_hashes();
      std::vector<std::string> sigs = policy.allowed_signature_methods();

      for(size_t i = 0; i != hashes.size(); ++i)
         for(size_t j = 0; j != sigs.size(); ++j)
            m_supported_algos.push_back(std::make_pair(hashes[i], sigs[j]));
      }

   send(writer, hash);
   }

/**
* Deserialize a Certificate Request message
*/
Certificate_Req::Certificate_Req(const MemoryRegion<byte>& buf,
                                 Version_Code version)
   {
   if(buf.size() < 4)
      throw Decoding_Error("Certificate_Req: Bad certificate request");

   TLS_Data_Reader reader(buf);

   cert_types = reader.get_range_vector<byte>(1, 1, 255);

   if(version >= TLS_V12)
      {
      std::vector<byte> sig_hash_algs = reader.get_range_vector<byte>(2, 2, 65534);

      if(sig_hash_algs.size() % 2 != 0)
         throw Decoding_Error("Bad length for signature IDs in certificate request");

      for(size_t i = 0; i != sig_hash_algs.size(); i += 2)
         {
         std::string hash = Signature_Algorithms::hash_algo_name(sig_hash_algs[i]);
         std::string sig = Signature_Algorithms::sig_algo_name(sig_hash_algs[i+1]);
         m_supported_algos.push_back(std::make_pair(hash, sig));
         }
      }
   else
      {
      // The hardcoded settings from previous protocol versions
      m_supported_algos.push_back(std::make_pair("TLS.Digest.0", "RSA"));
      m_supported_algos.push_back(std::make_pair("SHA-1", "DSA"));
      m_supported_algos.push_back(std::make_pair("SHA-1", "ECDSA"));
      }

   u16bit purported_size = reader.get_u16bit();

   if(reader.remaining_bytes() != purported_size)
      throw Decoding_Error("Inconsistent length in certificate request");

   while(reader.has_remaining())
      {
      std::vector<byte> name_bits = reader.get_range_vector<byte>(2, 0, 65535);

      BER_Decoder decoder(&name_bits[0], name_bits.size());
      X509_DN name;
      decoder.decode(name);
      names.push_back(name);
      }
   }

/**
* Serialize a Certificate Request message
*/
MemoryVector<byte> Certificate_Req::serialize() const
   {
   MemoryVector<byte> buf;

   append_tls_length_value(buf, cert_types, 1);

   if(!m_supported_algos.empty())
      {
      buf += Signature_Algorithms(m_supported_algos).serialize();
      }

   for(size_t i = 0; i != names.size(); ++i)
      {
      DER_Encoder encoder;
      encoder.encode(names[i]);

      append_tls_length_value(buf, encoder.get_contents(), 2);
      }

   return buf;
   }

/**
* Create a new Certificate message
*/
Certificate::Certificate(Record_Writer& writer,
                         Handshake_Hash& hash,
                         const std::vector<X509_Certificate>& cert_list)
   {
   certs = cert_list;
   send(writer, hash);
   }

/**
* Deserialize a Certificate message
*/
Certificate::Certificate(const MemoryRegion<byte>& buf)
   {
   if(buf.size() < 3)
      throw Decoding_Error("Certificate: Message malformed");

   const size_t total_size = make_u32bit(0, buf[0], buf[1], buf[2]);

   SecureQueue queue;
   queue.write(&buf[3], buf.size() - 3);

   if(queue.size() != total_size)
      throw Decoding_Error("Certificate: Message malformed");

   while(queue.size())
      {
      if(queue.size() < 3)
         throw Decoding_Error("Certificate: Message malformed");

      byte len[3];
      queue.read(len, 3);

      const size_t cert_size = make_u32bit(0, len[0], len[1], len[2]);
      const size_t original_size = queue.size();

      X509_Certificate cert(queue);
      if(queue.size() + cert_size != original_size)
         throw Decoding_Error("Certificate: Message malformed");
      certs.push_back(cert);
      }
   }

/**
* Serialize a Certificate message
*/
MemoryVector<byte> Certificate::serialize() const
   {
   MemoryVector<byte> buf(3);

   for(size_t i = 0; i != certs.size(); ++i)
      {
      MemoryVector<byte> raw_cert = certs[i].BER_encode();
      const size_t cert_size = raw_cert.size();
      for(size_t i = 0; i != 3; ++i)
         buf.push_back(get_byte<u32bit>(i+1, cert_size));
      buf += raw_cert;
      }

   const size_t buf_size = buf.size() - 3;
   for(size_t i = 0; i != 3; ++i)
      buf[i] = get_byte<u32bit>(i+1, buf_size);

   return buf;
   }

}

}
