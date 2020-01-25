/*
* TLS Blocking API
* (C) 2013 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_blocking.h>

namespace Botan {

namespace TLS {

Blocking_Client::Blocking_Client(read_fn reader,
                                 write_fn writer,
                                 Session_Manager& session_manager,
                                 Credentials_Manager& creds,
                                 const Policy& policy,
                                 RandomNumberGenerator& rng,
                                 const Server_Information& server_info,
                                 const Protocol_Version& offer_version,
                                 const std::vector<std::string>& next) :
   m_read(reader),
   m_callbacks(new TLS::Compat_Callbacks(
                  /*
                  we are ok using deprecated features here because the whole Blocking_Client class
                  is also deprecated, so just silence the warning.
                  */
               TLS::Compat_Callbacks::SILENCE_DEPRECATION_WARNING::PLEASE,
               writer,
               std::bind(&Blocking_Client::data_cb, this, std::placeholders::_1, std::placeholders::_2),
               std::function<void (Alert)>(std::bind(&Blocking_Client::alert_cb, this, std::placeholders::_1)),
               std::bind(&Blocking_Client::handshake_cb, this, std::placeholders::_1)
             )),
   m_channel(*m_callbacks.get(),
             session_manager,
             creds,
             policy,
             rng,
             server_info,
             offer_version,
             next)
   {
   }

bool Blocking_Client::handshake_cb(const Session& session)
   {
   return this->handshake_complete(session);
   }

void Blocking_Client::alert_cb(const Alert& alert)
   {
   this->alert_notification(alert);
   }

void Blocking_Client::data_cb(const uint8_t data[], size_t data_len)
   {
   m_plaintext.insert(m_plaintext.end(), data, data + data_len);
   }

void Blocking_Client::do_handshake()
   {
   std::vector<uint8_t> readbuf(4096);

   while(!m_channel.is_closed() && !m_channel.is_active())
      {
      const size_t from_socket = m_read(readbuf.data(), readbuf.size());
      m_channel.received_data(readbuf.data(), from_socket);
      }
   }

size_t Blocking_Client::read(uint8_t buf[], size_t buf_len)
   {
   std::vector<uint8_t> readbuf(4096);

   while(m_plaintext.empty() && !m_channel.is_closed())
      {
      const size_t from_socket = m_read(readbuf.data(), readbuf.size());
      m_channel.received_data(readbuf.data(), from_socket);
      }

   const size_t returned = std::min(buf_len, m_plaintext.size());

   for(size_t i = 0; i != returned; ++i)
      buf[i] = m_plaintext[i];
   m_plaintext.erase(m_plaintext.begin(), m_plaintext.begin() + returned);

   BOTAN_ASSERT_IMPLICATION(returned == 0, m_channel.is_closed(),
                            "Only return zero if channel is closed");

   return returned;
   }

}

}
