/*
* TLS Session Management
* (C) 2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef TLS_SESSION_STATE_H_
#define TLS_SESSION_STATE_H_

#include <botan/tls_magic.h>
#include <botan/secmem.h>
#include <vector>
#include <map>

#include <iostream>

namespace Botan {

struct BOTAN_DLL TLS_Session_Params
   {
   SecureVector<byte> master_secret;
   std::vector<byte> client_random;
   std::vector<byte> server_random;

   bool resumable;
   Version_Code version;
   Connection_Side connection_side;
   Ciphersuite_Code ciphersuite;
   Compression_Algo compression_method;
   };

/**
* TLS_Session_Manager is an interface to systems which can save
* session parameters for support session resumption.
*/
class BOTAN_DLL TLS_Session_Manager
   {
   public:
      /**
      * Try to load a saved session
      * @param session_id the session identifier we are trying to resume
      * @param params will be set to the saved session data (if found),
               or not modified if not found
      * @return true if params was modified
      */
      virtual bool find(const std::vector<byte>& session_id,
                        TLS_Session_Params& params) = 0;

      /**
      * Prohibit resumption of this session. Effectively an erase.
      */
      virtual void prohibit_resumption(const std::vector<byte>& session_id) = 0;

      /**
      * Save a session on a best effort basis; the manager may not in
      * fact be able to save the session for whatever reason, this is
      * not an error. Caller cannot assume that calling save followed
      * immediately by find will result in a successful lookup.
      *
      * @param session_id the session identifier
      * @param params to save
      */
      virtual void save(const std::vector<byte>& session_id,
                        const TLS_Session_Params& params) = 0;

      virtual ~TLS_Session_Manager() {}
   };

/**
* A simple implementation of TLS_Session_Manager that just saves
* values in memory, with no persistance abilities
*/
class BOTAN_DLL TLS_Session_Manager_In_Memory : public TLS_Session_Manager
   {
   public:
      /**
      * @param max_sessions a hint on the maximum number of sessions
      * to save at any one time.
      */
      TLS_Session_Manager_In_Memory(size_t max_sessions = 0) :
         max_sessions(max_sessions) {}

      bool find(const std::vector<byte>& session_id,
                TLS_Session_Params& params)
         {
         std::map<std::vector<byte>, TLS_Session_Params>::const_iterator i =
            sessions.find(session_id);

         std::cout << "Know about " << sessions.size() << " sessions\n";

         if(i != sessions.end())
            {
            params = i->second;
            return true;
            }

         return false;
         }

      void prohibit_resumption(const std::vector<byte>& session_id)
         {
         std::map<std::vector<byte>, TLS_Session_Params>::iterator i =
            sessions.find(session_id);

         if(i != sessions.end())
            sessions.erase(i);
         }

      void save(const std::vector<byte>& session_id,
                const TLS_Session_Params& session_data)
         {
         if(max_sessions != 0)
            {
            while(sessions.size() >= max_sessions)
               sessions.erase(sessions.begin());
            }

         sessions[session_id] = session_data;
         }

   private:
      size_t max_sessions;
      std::map<std::vector<byte>, TLS_Session_Params> sessions;
   };

}

#endif
