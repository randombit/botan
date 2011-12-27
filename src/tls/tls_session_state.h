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
#include <botan/hex.h>
#include <vector>
#include <map>

#include <iostream>

namespace Botan {

/**
* Class representing a TLS session state
*
* @todo Support serialization to make it easier for session managers
*/
struct BOTAN_DLL TLS_Session_Params
   {
   u16bit version;
   u16bit ciphersuite;
   byte compression_method;
   Connection_Side connection_side;

   SecureVector<byte> master_secret;
   };

/**
* TLS_Session_Manager is an interface to systems which can save
* session parameters for support session resumption.
*
* Implementations should strive to be thread safe
*/
class BOTAN_DLL TLS_Session_Manager
   {
   public:
      /**
      * Try to load a saved session
      * @param session_id the session identifier we are trying to resume
      * @param params will be set to the saved session data (if found),
               or not modified if not found
      * @param which side of the connection we are
      * @return true if params was modified
      */
      virtual bool find(const std::vector<byte>& session_id,
                        TLS_Session_Params& params,
                        Connection_Side side) = 0;

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
*
* @todo add locking
*/
class BOTAN_DLL TLS_Session_Manager_In_Memory : public TLS_Session_Manager
   {
   public:
      /**
      * @param max_sessions a hint on the maximum number of sessions
      *        to save at any one time. (If zero, don't cap at all)
      * @param session_lifetime sesions are expired after this many
      *         seconds have elapsed.
      */
      TLS_Session_Manager_In_Memory(size_t max_sessions = 10000,
                                    size_t session_lifetime = 86400) :
         max_sessions(max_sessions),
         session_lifetime(session_lifetime)
            {}

      bool find(const std::vector<byte>& session_id,
                TLS_Session_Params& params,
                Connection_Side side)
         {
         const std::string session_id_str =
            hex_encode(&session_id[0], session_id.size());

         std::map<std::string, TLS_Session_Params>::const_iterator i =
            sessions.find(session_id_str);

         std::cout << "Client asked about " << session_id_str << "\n";

         std::cout << "Know about " << sessions.size() << " sessions\n";

         for(std::map<std::string, TLS_Session_Params>::const_iterator j =
                sessions.begin(); j != sessions.end(); ++j)
            std::cout << "Session " << j->first << "\n";

         if(i != sessions.end() && i->second.connection_side == side)
            {
            params = i->second;
            return true;
            }

         return false;
         }

      void prohibit_resumption(const std::vector<byte>& session_id)
         {
         const std::string session_id_str =
            hex_encode(&session_id[0], session_id.size());

         std::map<std::string, TLS_Session_Params>::iterator i =
            sessions.find(session_id_str);

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

         const std::string session_id_str =
            hex_encode(&session_id[0], session_id.size());

         sessions[session_id_str] = session_data;
         }

   private:
      size_t max_sessions, session_lifetime;
      std::map<std::string, TLS_Session_Params> sessions;
   };

}

#endif
