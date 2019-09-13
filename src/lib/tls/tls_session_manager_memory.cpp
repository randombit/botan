/*
* TLS Session Management
* (C) 2011,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_session_manager.h>
#include <botan/hex.h>
#include <botan/rng.h>
#include <chrono>

namespace Botan {

namespace TLS {

Session_Manager_In_Memory::Session_Manager_In_Memory(
   RandomNumberGenerator& rng,
   size_t max_sessions,
   std::chrono::seconds session_lifetime) :
   m_max_sessions(max_sessions),
   m_session_lifetime(session_lifetime),
   m_rng(rng),
   m_session_key(m_rng.random_vec(32))
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
   const std::vector<uint8_t>& session_id, Session& session)
   {
   lock_guard_type<mutex_type> lock(m_mutex);

   return load_from_session_str(hex_encode(session_id), session);
   }

bool Session_Manager_In_Memory::load_from_server_info(
   const Server_Information& info, Session& session)
   {
   lock_guard_type<mutex_type> lock(m_mutex);

   auto i = m_info_sessions.find(info);

   if(i == m_info_sessions.end())
      return false;

   if(load_from_session_str(i->second, session))
      return true;

   /*
   * It existed at one point but was removed from the sessions map,
   * remove m_info_sessions entry as well
   */
   m_info_sessions.erase(i);

   return false;
   }

void Session_Manager_In_Memory::remove_entry(
   const std::vector<uint8_t>& session_id)
   {
   lock_guard_type<mutex_type> lock(m_mutex);

   auto i = m_sessions.find(hex_encode(session_id));

   if(i != m_sessions.end())
      m_sessions.erase(i);
   }

size_t Session_Manager_In_Memory::remove_all()
   {
   const size_t removed = m_sessions.size();
   m_info_sessions.clear();
   m_sessions.clear();
   m_rng.random_vec(m_session_key, 32);
   return removed;
   }

void Session_Manager_In_Memory::save(const Session& session)
   {
   lock_guard_type<mutex_type> lock(m_mutex);

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

   if(session.side() == CLIENT && !session.server_info().empty())
      m_info_sessions[session.server_info()] = session_id_str;
   }

}

}
