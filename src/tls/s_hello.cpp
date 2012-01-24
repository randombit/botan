;/*
* TLS Server Hello and Server Hello Done
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_extensions.h>
#include <botan/tls_record.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace TLS {

/*
* Create a new Server Hello message
*/
Server_Hello::Server_Hello(Record_Writer& writer,
                           Handshake_Hash& hash,
                           Protocol_Version version,
                           const Client_Hello& c_hello,
                           const std::vector<std::string>& available_cert_types,
                           const Policy& policy,
                           bool client_has_secure_renegotiation,
                           const MemoryRegion<byte>& reneg_info,
                           bool client_has_npn,
                           const std::vector<std::string>& next_protocols,
                           RandomNumberGenerator& rng) :
   s_version(version),
   m_session_id(rng.random_vec(32)),
   s_random(make_hello_random(rng)),
   m_fragment_size(c_hello.fragment_size()),
   m_secure_renegotiation(client_has_secure_renegotiation),
   m_renegotiation_info(reneg_info),
   m_next_protocol(client_has_npn),
   m_next_protocols(next_protocols)
   {
   suite = policy.choose_suite(
      c_hello.ciphersuites(),
      available_cert_types,
      policy.choose_curve(c_hello.supported_ecc_curves()) != "",
      false);

   if(suite == 0)
      throw TLS_Exception(HANDSHAKE_FAILURE,
                          "Can't agree on a ciphersuite with client");

   comp_method = policy.choose_compression(c_hello.compression_methods());

   send(writer, hash);
   }

/*
* Create a new Server Hello message
*/
Server_Hello::Server_Hello(Record_Writer& writer,
                           Handshake_Hash& hash,
                           const MemoryRegion<byte>& session_id,
                           Protocol_Version ver,
                           u16bit ciphersuite,
                           byte compression,
                           size_t max_fragment_size,
                           bool client_has_secure_renegotiation,
                           const MemoryRegion<byte>& reneg_info,
                           bool client_has_npn,
                           const std::vector<std::string>& next_protocols,
                           RandomNumberGenerator& rng) :
   s_version(ver),
   m_session_id(session_id),
   s_random(make_hello_random(rng)),
   suite(ciphersuite),
   comp_method(compression),
   m_fragment_size(max_fragment_size),
   m_secure_renegotiation(client_has_secure_renegotiation),
   m_renegotiation_info(reneg_info),
   m_next_protocol(client_has_npn),
   m_next_protocols(next_protocols)
   {
   send(writer, hash);
   }

/*
* Deserialize a Server Hello message
*/
Server_Hello::Server_Hello(const MemoryRegion<byte>& buf)
   {
   m_secure_renegotiation = false;
   m_next_protocol = false;

   if(buf.size() < 38)
      throw Decoding_Error("Server_Hello: Packet corrupted");

   TLS_Data_Reader reader(buf);

   const byte major_version = reader.get_byte();
   const byte minor_version = reader.get_byte();

   s_version = Protocol_Version(major_version, minor_version);

   if(s_version != Protocol_Version::SSL_V3 &&
      s_version != Protocol_Version::TLS_V10 &&
      s_version != Protocol_Version::TLS_V11 &&
      s_version != Protocol_Version::TLS_V12)
      {
      throw TLS_Exception(PROTOCOL_VERSION,
                          "Server_Hello: Unsupported server version");
      }

   s_random = reader.get_fixed<byte>(32);

   m_session_id = reader.get_range<byte>(1, 0, 32);

   suite = reader.get_u16bit();

   comp_method = reader.get_byte();

   Extensions extensions(reader);

   if(Renegotation_Extension* reneg = extensions.get<Renegotation_Extension>())
      {
      // checked by Client / Server as they know the handshake state
      m_secure_renegotiation = true;
      m_renegotiation_info = reneg->renegotiation_info();
      }

   if(Next_Protocol_Notification* npn = extensions.get<Next_Protocol_Notification>())
      {
      m_next_protocols = npn->protocols();
      m_next_protocol = true;
      }
   }

/*
* Serialize a Server Hello message
*/
MemoryVector<byte> Server_Hello::serialize() const
   {
   MemoryVector<byte> buf;

   buf.push_back(s_version.major_version());
   buf.push_back(s_version.minor_version());
   buf += s_random;

   append_tls_length_value(buf, m_session_id, 1);

   buf.push_back(get_byte(0, suite));
   buf.push_back(get_byte(1, suite));

   buf.push_back(comp_method);

   Extensions extensions;

   if(m_secure_renegotiation)
      extensions.add(new Renegotation_Extension(m_renegotiation_info));

   if(m_fragment_size != 0)
      extensions.add(new Maximum_Fragment_Length(m_fragment_size));

   if(m_next_protocol)
      extensions.add(new Next_Protocol_Notification(m_next_protocols));

   buf += extensions.serialize();

   return buf;
   }

/*
* Create a new Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(Record_Writer& writer,
                                     Handshake_Hash& hash)
   {
   send(writer, hash);
   }

/*
* Deserialize a Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(const MemoryRegion<byte>& buf)
   {
   if(buf.size())
      throw Decoding_Error("Server_Hello_Done: Must be empty, and is not");
   }

/*
* Serialize a Server Hello Done message
*/
MemoryVector<byte> Server_Hello_Done::serialize() const
   {
   return MemoryVector<byte>();
   }

}

}
