/*
* TLS Session Management
* (C) 2011,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_session_manager.h>
#include <botan/libstate.h>
#include <botan/hex.h>
#include <chrono>

namespace Botan {

namespace TLS {

Session_Manager_In_Memory::Session_Manager_In_Memory(
   size_t max_sessions, std::chrono::seconds session_lifetime) :
   m_max_sessions(max_sessions),
   m_session_lifetime(session_lifetime),
   m_rng(global_state().global_rng()),
   m_session_key(m_rng, 32)
   {}

bool Session_Manager_In_Memory::load_from_session_str(
   const std::string& session_str, Session& session)
   {
   // assert(lock is held)

   auto i = m_sessions.find(session_str);

   if(i == m_sessions.end())
      return false;

   try
      {
      session = Session::decrypt(i->second, m_session_key);
      }
   catch(...)
      {
      return false;
      }

   // if session has expired, remove it
   const auto now = std::chrono::system_clock::now();

   if(session.start_time() + session_lifetime() < now)
      {
      m_sessions.erase(i);
      return false;
      }

   return true;
   }

bool Session_Manager_In_Memory::load_from_session_id(
   const std::vector<byte>& session_id, Session& session)
   {
   std::lock_guard<std::mutex> lock(m_mutex);

   return load_from_session_str(hex_encode(session_id), session);
   }

bool Session_Manager_In_Memory::load_from_host_info(
   const std::string& hostname, u16bit port, Session& session)
   {
   std::lock_guard<std::mutex> lock(m_mutex);

   auto i = m_host_sessions.find(hostname + ":" + std::to_string(port));

   if(i == m_host_sessions.end())
      {
      if(port > 0)
         i = m_host_sessions.find(hostname + ":" + std::to_string(0));

      if(i == m_host_sessions.end())
         return false;
      }

   if(load_from_session_str(i->second, session))
      return true;

   // was removed from sessions map, remove m_host_sessions entry
   m_host_sessions.erase(i);

   return false;
   }

void Session_Manager_In_Memory::remove_entry(
   const std::vector<byte>& session_id)
   {
   std::lock_guard<std::mutex> lock(m_mutex);

   auto i = m_sessions.find(hex_encode(session_id));

   if(i != m_sessions.end())
      m_sessions.erase(i);
   }

void Session_Manager_In_Memory::save(const Session& session, u16bit port)
   {
   std::lock_guard<std::mutex> lock(m_mutex);

   if(m_max_sessions != 0)
      {
      /*
      We generate new session IDs with the first 4 bytes being a
      timestamp, so this actually removes the oldest sessions first.
      */
      while(m_sessions.size() >= m_max_sessions)
         m_sessions.erase(m_sessions.begin());
      }

   const std::string session_id_str = hex_encode(session.session_id());

   m_sessions[session_id_str] = session.encrypt(m_session_key, m_rng);

   const std::string hostname = session.sni_hostname();

   if(session.side() == CLIENT && hostname != "")
      m_host_sessions[hostname + ":" + std::to_string(port)] = session_id_str;
   }

}

}
