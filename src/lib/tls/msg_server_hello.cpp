/*
* TLS Server Hello and Server Hello Done
* (C) 2004-2011,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_extensions.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace TLS {

// New session case
Server_Hello::Server_Hello(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           RandomNumberGenerator& rng,
                           const std::vector<byte>& reneg_info,
                           const Client_Hello& client_hello,
                           const std::vector<byte>& new_session_id,
                           Protocol_Version new_session_version,
                           u16bit ciphersuite,
                           byte compression,
                           bool offer_session_ticket,
                           const std::string& next_protocol) :
   m_version(new_session_version),
   m_session_id(new_session_id),
   m_random(make_hello_random(rng, policy)),
   m_ciphersuite(ciphersuite),
   m_comp_method(compression)
   {
   if(client_hello.supports_extended_master_secret())
      m_extensions.add(new Extended_Master_Secret);

   if(client_hello.secure_renegotiation())
      m_extensions.add(new Renegotiation_Extension(reneg_info));

   if(client_hello.supports_session_ticket() && offer_session_ticket)
      m_extensions.add(new Session_Ticket());

   if(!next_protocol.empty() && client_hello.supports_alpn())
      m_extensions.add(new Application_Layer_Protocol_Notification(next_protocol));

   if(m_version.is_datagram_protocol())
      {
      const std::vector<u16bit> server_srtp = policy.srtp_profiles();
      const std::vector<u16bit> client_srtp = client_hello.srtp_profiles();

      if(!server_srtp.empty() && !client_srtp.empty())
         {
         u16bit shared = 0;
         // always using server preferences for now
         for(auto s : server_srtp)
            for(auto c : client_srtp)
               {
               if(shared == 0 && s == c)
                  shared = s;
               }

         if(shared)
            m_extensions.add(new SRTP_Protection_Profiles(shared));
         }
      }

   hash.update(io.send(*this));
   }

// Resuming
Server_Hello::Server_Hello(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           RandomNumberGenerator& rng,
                           const std::vector<byte>& reneg_info,
                           const Client_Hello& client_hello,
                           Session& resumed_session,
                           bool offer_session_ticket,
                           const std::string& next_protocol) :
   m_version(resumed_session.version()),
   m_session_id(client_hello.session_id()),
   m_random(make_hello_random(rng, policy)),
   m_ciphersuite(resumed_session.ciphersuite_code()),
   m_comp_method(resumed_session.compression_method())
   {
   if(client_hello.supports_extended_master_secret())
      m_extensions.add(new Extended_Master_Secret);

   if(client_hello.secure_renegotiation())
      m_extensions.add(new Renegotiation_Extension(reneg_info));

   if(client_hello.supports_session_ticket() && offer_session_ticket)
      m_extensions.add(new Session_Ticket());

   if(!next_protocol.empty() && client_hello.supports_alpn())
      m_extensions.add(new Application_Layer_Protocol_Notification(next_protocol));

   hash.update(io.send(*this));
   }

/*
* Deserialize a Server Hello message
*/
Server_Hello::Server_Hello(const std::vector<byte>& buf)
   {
   if(buf.size() < 38)
      throw Decoding_Error("Server_Hello: Packet corrupted");

   TLS_Data_Reader reader("ServerHello", buf);

   const byte major_version = reader.get_byte();
   const byte minor_version = reader.get_byte();

   m_version = Protocol_Version(major_version, minor_version);

   m_random = reader.get_fixed<byte>(32);

   m_session_id = reader.get_range<byte>(1, 0, 32);

   m_ciphersuite = reader.get_u16bit();

   m_comp_method = reader.get_byte();

   m_extensions.deserialize(reader);
   }

/*
* Serialize a Server Hello message
*/
std::vector<byte> Server_Hello::serialize() const
   {
   std::vector<byte> buf;

   buf.push_back(m_version.major_version());
   buf.push_back(m_version.minor_version());
   buf += m_random;

   append_tls_length_value(buf, m_session_id, 1);

   buf.push_back(get_byte(0, m_ciphersuite));
   buf.push_back(get_byte(1, m_ciphersuite));

   buf.push_back(m_comp_method);

   buf += m_extensions.serialize();

   return buf;
   }

/*
* Create a new Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(Handshake_IO& io,
                                     Handshake_Hash& hash)
   {
   hash.update(io.send(*this));
   }

/*
* Deserialize a Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(const std::vector<byte>& buf)
   {
   if(buf.size())
      throw Decoding_Error("Server_Hello_Done: Must be empty, and is not");
   }

/*
* Serialize a Server Hello Done message
*/
std::vector<byte> Server_Hello_Done::serialize() const
   {
   return std::vector<byte>();
   }

}

}
