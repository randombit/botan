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

/*
* Create a new Server Hello message
*/
Server_Hello::Server_Hello(Record_Writer& writer,
                           TLS_Handshake_Hash& hash,
                           Version_Code version,
                           const Client_Hello& c_hello,
                           const std::vector<X509_Certificate>& certs,
                           const TLS_Policy& policy,
                           bool client_has_secure_renegotiation,
                           const MemoryRegion<byte>& reneg_info,
                           bool client_has_npn,
                           const std::vector<std::string>& next_protocols,
                           RandomNumberGenerator& rng) :
   s_version(version),
   m_session_id(rng.random_vec(32)),
   s_random(rng.random_vec(32)),
   m_fragment_size(c_hello.fragment_size()),
   m_secure_renegotiation(client_has_secure_renegotiation),
   m_renegotiation_info(reneg_info),
   m_next_protocol(client_has_npn),
   m_next_protocols(next_protocols)
   {
   bool have_rsa = false, have_dsa = false;

   for(size_t i = 0; i != certs.size(); ++i)
      {
      Public_Key* key = certs[i].subject_public_key();
      if(key->algo_name() == "RSA")
         have_rsa = true;

      if(key->algo_name() == "DSA")
         have_dsa = true;
      }

   suite = policy.choose_suite(c_hello.ciphersuites(), have_rsa, have_dsa, false);

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
                           TLS_Handshake_Hash& hash,
                           const MemoryRegion<byte>& session_id,
                           Version_Code ver,
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
   s_random(rng.random_vec(32)),
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
* Serialize a Server Hello message
*/
MemoryVector<byte> Server_Hello::serialize() const
   {
   MemoryVector<byte> buf;

   buf.push_back(static_cast<byte>(s_version >> 8));
   buf.push_back(static_cast<byte>(s_version     ));
   buf += s_random;

   append_tls_length_value(buf, m_session_id, 1);

   buf.push_back(get_byte(0, suite));
   buf.push_back(get_byte(1, suite));

   buf.push_back(comp_method);

   TLS_Extensions extensions;

   if(m_secure_renegotiation)
      extensions.push_back(new Renegotation_Extension(m_renegotiation_info));

   if(m_fragment_size != 0)
      extensions.push_back(new Maximum_Fragment_Length(m_fragment_size));

   if(m_next_protocol)
      extensions.push_back(new Next_Protocol_Negotiation(m_next_protocols));

   buf += extensions.serialize();

   return buf;
   }

/*
* Deserialize a Server Hello message
*/
void Server_Hello::deserialize(const MemoryRegion<byte>& buf)
   {
   m_secure_renegotiation = false;
   m_next_protocol = false;

   if(buf.size() < 38)
      throw Decoding_Error("Server_Hello: Packet corrupted");

   TLS_Data_Reader reader(buf);

   s_version = static_cast<Version_Code>(reader.get_u16bit());

   if(s_version != SSL_V3 && s_version != TLS_V10 && s_version != TLS_V11)
      {
      throw TLS_Exception(PROTOCOL_VERSION,
                          "Server_Hello: Unsupported server version");
      }

   s_random = reader.get_fixed<byte>(32);

   m_session_id = reader.get_range<byte>(1, 0, 32);

   suite = reader.get_u16bit();

   comp_method = reader.get_byte();

   TLS_Extensions extensions(reader);

   for(size_t i = 0; i != extensions.count(); ++i)
      {
      TLS_Extension* extn = extensions.at(i);

      if(Renegotation_Extension* reneg = dynamic_cast<Renegotation_Extension*>(extn))
         {
         // checked by TLS_Client / TLS_Server as they know the handshake state
         m_secure_renegotiation = true;
         m_renegotiation_info = reneg->renegotiation_info();
         }
      else if(Next_Protocol_Negotiation* npn = dynamic_cast<Next_Protocol_Negotiation*>(extn))
         {
         m_next_protocols = npn->protocols();
         m_next_protocol = true;
         }
      }
   }

/*
* Create a new Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(Record_Writer& writer,
                                     TLS_Handshake_Hash& hash)
   {
   send(writer, hash);
   }

/*
* Serialize a Server Hello Done message
*/
MemoryVector<byte> Server_Hello_Done::serialize() const
   {
   return MemoryVector<byte>();
   }

/*
* Deserialize a Server Hello Done message
*/
void Server_Hello_Done::deserialize(const MemoryRegion<byte>& buf)
   {
   if(buf.size())
      throw Decoding_Error("Server_Hello_Done: Must be empty, and is not");
   }

}
