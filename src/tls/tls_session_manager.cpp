/*
* TLS Session Management
* (C) 2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_session_manager.h>
#include <botan/hex.h>
#include <botan/time.h>

namespace Botan {

bool TLS_Session_Manager_In_Memory::load_from_session_str(
   const std::string& session_str, TLS_Session& session)
   {
   std::map<std::string, TLS_Session>::iterator i = sessions.find(session_str);

   if(i == sessions.end())
      return false;

   // session has expired, remove it
   const u64bit now = system_time();
   if(i->second.start_time() + session_lifetime >= now)
      {
      sessions.erase(i);
      return false;
      }

   session = i->second;
   return true;
   }

bool TLS_Session_Manager_In_Memory::load_from_session_id(
   const MemoryVector<byte>& session_id, TLS_Session& session)
   {
   return load_from_session_str(hex_encode(session_id), session);
   }

bool TLS_Session_Manager_In_Memory::load_from_host_info(
   const std::string& hostname, u16bit port, TLS_Session& session)
   {
   std::map<std::string, std::string>::iterator i;

   if(port > 0)
      i = host_sessions.find(hostname + ":" + to_string(port));
   else
      i = host_sessions.find(hostname);

   if(i == host_sessions.end())
      return false;

   if(load_from_session_str(i->second, session))
      return true;

   // was removed from sessions map, remove host_sessions entry
   host_sessions.erase(i);

   return false;
   }

void TLS_Session_Manager_In_Memory::remove_entry(
   const MemoryVector<byte>& session_id)
   {
   std::map<std::string, TLS_Session>::iterator i =
      sessions.find(hex_encode(session_id));

   if(i != sessions.end())
      sessions.erase(i);
   }

void TLS_Session_Manager_In_Memory::save(const TLS_Session& session)
   {
   if(max_sessions != 0)
      {
      /*
      This removes randomly based on ordering of session ids.
      Instead, remove oldest first?
      */
      while(sessions.size() >= max_sessions)
         sessions.erase(sessions.begin());
      }

   const std::string session_id_str = hex_encode(session.session_id());

   sessions[session_id_str] = session;

   if(session.side() == CLIENT && session.sni_hostname() != "")
      host_sessions[session.sni_hostname()] = session_id_str;
   }

}
