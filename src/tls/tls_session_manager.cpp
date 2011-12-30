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

bool TLS_Session_Manager_In_Memory::find(const MemoryVector<byte>& session_id,
                                         TLS_Session& params)
   {
   std::map<std::string, TLS_Session>::iterator i =
      sessions.find(hex_encode(session_id));

   if(i == sessions.end())
      return false;

   // session has expired, remove it
   const u64bit now = system_time();
   if(i->second.start_time() + session_lifetime >= now)
      {
      sessions.erase(i);
      return false;
      }

   params = i->second;
   return true;
   }

bool TLS_Session_Manager_In_Memory::find(const std::string& hostname, u16bit port,
                                         TLS_Session& params)
   {
   return false;
   }

void TLS_Session_Manager_In_Memory::prohibit_resumption(
   const MemoryVector<byte>& session_id)
   {
   std::map<std::string, TLS_Session>::iterator i =
      sessions.find(hex_encode(session_id));

   if(i != sessions.end())
      sessions.erase(i);
   }

void TLS_Session_Manager_In_Memory::save(const TLS_Session& session_data)
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

   sessions[hex_encode(session_data.session_id())] = session_data;
   }

}
