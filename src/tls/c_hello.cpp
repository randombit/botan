/*
* TLS Hello Request and Client Hello Messages
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
#include <chrono>

namespace Botan {

namespace TLS {

enum {
   TLS_EMPTY_RENEGOTIATION_INFO_SCSV        = 0x00FF
};

std::vector<byte> make_hello_random(RandomNumberGenerator& rng)
   {
   std::vector<byte> buf(32);

   const u32bit time32 = static_cast<u32bit>(
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

   store_be(time32, &buf[0]);
   rng.randomize(&buf[4], buf.size() - 4);
   return buf;
   }

/*
* Create a new Hello Request message
*/
Hello_Request::Hello_Request(Record_Writer& writer)
   {
   writer.send(*this);
   }

/*
* Deserialize a Hello Request message
*/
Hello_Request::Hello_Request(const std::vector<byte>& buf)
   {
   if(buf.size())
      throw Decoding_Error("Bad Hello_Request, has non-zero size");
   }

/*
* Serialize a Hello Request message
*/
std::vector<byte> Hello_Request::serialize() const
   {
   return std::vector<byte>();
   }

/*
* Create a new Client Hello message
*/
Client_Hello::Client_Hello(Record_Writer& writer,
                           Handshake_Hash& hash,
                           Protocol_Version version,
                           const Policy& policy,
                           RandomNumberGenerator& rng,
                           const std::vector<byte>& reneg_info,
                           bool next_protocol,
                           const std::string& hostname,
                           const std::string& srp_identifier) :
   m_version(version),
   m_random(make_hello_random(rng)),
   m_suites(ciphersuite_list(policy, (srp_identifier != ""))),
   m_comp_methods(policy.compression()),
   m_hostname(hostname),
   m_srp_identifier(srp_identifier),
   m_next_protocol(next_protocol),
   m_fragment_size(0),
   m_secure_renegotiation(true),
   m_renegotiation_info(reneg_info),
   m_supported_curves(policy.allowed_ecc_curves()),
   m_supports_session_ticket(true),
   m_supports_heartbeats(true),
   m_peer_can_send_heartbeats(true)
   {
   std::vector<std::string> hashes = policy.allowed_signature_hashes();
   std::vector<std::string> sigs = policy.allowed_signature_methods();

   for(size_t i = 0; i != hashes.size(); ++i)
      for(size_t j = 0; j != sigs.size(); ++j)
         m_supported_algos.push_back(std::make_pair(hashes[i], sigs[j]));

   hash.update(writer.send(*this));
   }

/*
* Create a new Client Hello message (session resumption case)
*/
Client_Hello::Client_Hello(Record_Writer& writer,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           RandomNumberGenerator& rng,
                           const std::vector<byte>& reneg_info,
                           const Session& session,
                           bool next_protocol) :
   m_version(session.version()),
   m_session_id(session.session_id()),
   m_random(make_hello_random(rng)),
   m_suites(ciphersuite_list(policy, (session.srp_identifier() != ""))),
   m_comp_methods(policy.compression()),
   m_hostname(session.sni_hostname()),
   m_srp_identifier(session.srp_identifier()),
   m_next_protocol(next_protocol),
   m_fragment_size(session.fragment_size()),
   m_secure_renegotiation(session.secure_renegotiation()),
   m_renegotiation_info(reneg_info),
   m_supported_curves(policy.allowed_ecc_curves()),
   m_supports_session_ticket(true),
   m_session_ticket(session.session_ticket()),
   m_supports_heartbeats(true),
   m_peer_can_send_heartbeats(true)
   {
   if(!value_exists(m_suites, session.ciphersuite_code()))
      m_suites.push_back(session.ciphersuite_code());

   if(!value_exists(m_comp_methods, session.compression_method()))
      m_comp_methods.push_back(session.compression_method());

   std::vector<std::string> hashes = policy.allowed_signature_hashes();
   std::vector<std::string> sigs = policy.allowed_signature_methods();

   for(size_t i = 0; i != hashes.size(); ++i)
      for(size_t j = 0; j != sigs.size(); ++j)
         m_supported_algos.push_back(std::make_pair(hashes[i], sigs[j]));

   hash.update(writer.send(*this));
   }

/*
* Read a counterparty client hello
*/
Client_Hello::Client_Hello(const std::vector<byte>& buf, Handshake_Type type)
   {
   m_next_protocol = false;
   m_secure_renegotiation = false;
   m_supports_session_ticket = false;
   m_supports_heartbeats = false;
   m_peer_can_send_heartbeats = false;
   m_fragment_size = 0;

   if(type == CLIENT_HELLO)
      deserialize(buf);
   else
      deserialize_sslv2(buf);
   }

/*
* Serialize a Client Hello message
*/
std::vector<byte> Client_Hello::serialize() const
   {
   std::vector<byte> buf;

   buf.push_back(m_version.major_version());
   buf.push_back(m_version.minor_version());
   buf += m_random;

   append_tls_length_value(buf, m_session_id, 1);
   append_tls_length_value(buf, m_suites, 2);
   append_tls_length_value(buf, m_comp_methods, 1);

   /*
   * May not want to send extensions at all in some cases.
   * If so, should include SCSV value (if reneg info is empty, if
   * not we are renegotiating with a modern server and should only
   * send that extension.
   */

   Extensions extensions;

   if(m_secure_renegotiation)
      extensions.add(new Renegotation_Extension(m_renegotiation_info));

   extensions.add(new Session_Ticket(m_session_ticket));

   extensions.add(new Server_Name_Indicator(m_hostname));
   extensions.add(new SRP_Identifier(m_srp_identifier));

   extensions.add(new Supported_Elliptic_Curves(m_supported_curves));

   if(m_version.supports_negotiable_signature_algorithms())
      extensions.add(new Signature_Algorithms(m_supported_algos));

   extensions.add(new Heartbeat_Support_Indicator(true));

   if(m_renegotiation_info.empty() && m_next_protocol)
      extensions.add(new Next_Protocol_Notification());

   buf += extensions.serialize();

   return buf;
   }

void Client_Hello::deserialize_sslv2(const std::vector<byte>& buf)
   {
   if(buf.size() < 12 || buf[0] != 1)
      throw Decoding_Error("Client_Hello: SSLv2 hello corrupted");

   const size_t cipher_spec_len = make_u16bit(buf[3], buf[4]);
   const size_t m_session_id_len = make_u16bit(buf[5], buf[6]);
   const size_t challenge_len = make_u16bit(buf[7], buf[8]);

   const size_t expected_size =
      (9 + m_session_id_len + cipher_spec_len + challenge_len);

   if(buf.size() != expected_size)
      throw Decoding_Error("Client_Hello: SSLv2 hello corrupted");

   if(m_session_id_len != 0 || cipher_spec_len % 3 != 0 ||
      (challenge_len < 16 || challenge_len > 32))
      {
      throw Decoding_Error("Client_Hello: SSLv2 hello corrupted");
      }

   for(size_t i = 9; i != 9 + cipher_spec_len; i += 3)
      {
      if(buf[i] != 0) // a SSLv2 cipherspec; ignore it
         continue;

      m_suites.push_back(make_u16bit(buf[i+1], buf[i+2]));
      }

   m_version = Protocol_Version(buf[1], buf[2]);

   m_random.resize(challenge_len);
   copy_mem(&m_random[0], &buf[9+cipher_spec_len+m_session_id_len], challenge_len);

   m_secure_renegotiation =
      value_exists(m_suites, static_cast<u16bit>(TLS_EMPTY_RENEGOTIATION_INFO_SCSV));
   }

/*
* Deserialize a Client Hello message
*/
void Client_Hello::deserialize(const std::vector<byte>& buf)
   {
   if(buf.size() == 0)
      throw Decoding_Error("Client_Hello: Packet corrupted");

   if(buf.size() < 41)
      throw Decoding_Error("Client_Hello: Packet corrupted");

   TLS_Data_Reader reader(buf);

   const byte major_version = reader.get_byte();
   const byte minor_version = reader.get_byte();

   m_version = Protocol_Version(major_version, minor_version);

   m_random = reader.get_fixed<byte>(32);

   m_session_id = reader.get_range<byte>(1, 0, 32);

   m_suites = reader.get_range_vector<u16bit>(2, 1, 32767);

   m_comp_methods = reader.get_range_vector<byte>(1, 1, 255);

   Extensions extensions(reader);

   if(Server_Name_Indicator* sni = extensions.get<Server_Name_Indicator>())
      {
      m_hostname = sni->host_name();
      }

   if(SRP_Identifier* srp = extensions.get<SRP_Identifier>())
      {
      m_srp_identifier = srp->identifier();
      }

   if(Next_Protocol_Notification* npn = extensions.get<Next_Protocol_Notification>())
      {
      if(!npn->protocols().empty())
         throw Decoding_Error("Client sent non-empty NPN extension");

      m_next_protocol = true;
      }

   if(Maximum_Fragment_Length* frag = extensions.get<Maximum_Fragment_Length>())
      {
      m_fragment_size = frag->fragment_size();
      }

   if(Renegotation_Extension* reneg = extensions.get<Renegotation_Extension>())
      {
      // checked by Client / Server as they know the handshake state
      m_secure_renegotiation = true;
      m_renegotiation_info = reneg->renegotiation_info();
      }

   if(Supported_Elliptic_Curves* ecc = extensions.get<Supported_Elliptic_Curves>())
      m_supported_curves = ecc->curves();

   if(Signature_Algorithms* sigs = extensions.get<Signature_Algorithms>())
      {
      m_supported_algos = sigs->supported_signature_algorthms();
      }

   if(Maximum_Fragment_Length* frag = extensions.get<Maximum_Fragment_Length>())
      {
      m_fragment_size = frag->fragment_size();
      }

   if(Session_Ticket* ticket = extensions.get<Session_Ticket>())
      {
      m_supports_session_ticket = true;
      m_session_ticket = ticket->contents();
      }

   if(Heartbeat_Support_Indicator* hb = extensions.get<Heartbeat_Support_Indicator>())
      {
      m_supports_heartbeats = true;
      m_peer_can_send_heartbeats = hb->peer_allowed_to_send();
      }

   if(Renegotation_Extension* reneg = extensions.get<Renegotation_Extension>())
      {
      // checked by TLS_Client / TLS_Server as they know the handshake state
      m_secure_renegotiation = true;
      m_renegotiation_info = reneg->renegotiation_info();
      }

   if(value_exists(m_suites, static_cast<u16bit>(TLS_EMPTY_RENEGOTIATION_INFO_SCSV)))
      {
      /*
      * Clients are allowed to send both the extension and the SCSV
      * though it is not recommended. If it did, require that the
      * extension value be empty.
      */
      if(m_secure_renegotiation)
         {
         if(!m_renegotiation_info.empty())
            {
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Client send SCSV and non-empty extension");
            }
         }

      m_secure_renegotiation = true;
      m_renegotiation_info.clear();
      }
   }

/*
* Check if we offered this ciphersuite
*/
bool Client_Hello::offered_suite(u16bit ciphersuite) const
   {
   for(size_t i = 0; i != m_suites.size(); ++i)
      if(m_suites[i] == ciphersuite)
         return true;
   return false;
   }

}

}
