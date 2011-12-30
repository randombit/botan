/*
* TLS Session Manager
* (C) 2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef TLS_SESSION_MANAGER_H__
#define TLS_SESSION_MANAGER_H__

#include <botan/tls_session.h>
#include <map>

namespace Botan {

/**
* TLS_Session_Manager is an interface to systems which can save
* session parameters for supporting session resumption.
*
* Implementations should strive to be thread safe
*/
class BOTAN_DLL TLS_Session_Manager
   {
   public:
      /**
      * Try to load a saved session (server side)
      * @param session_id the session identifier we are trying to resume
      * @param params will be set to the saved session data (if found),
               or not modified if not found
      * @return true if params was modified
      */
      virtual bool find(const MemoryVector<byte>& session_id,
                        TLS_Session& params) = 0;

      /**
      * Try to load a saved session (client side)
      * @param hostname of the host we are connecting to
      * @param port the port number if we know it, or 0 if unknown
      * @param params will be set to the saved session data (if found),
               or not modified if not found
      * @return true if params was modified
      */
      virtual bool find(const std::string& hostname, u16bit port,
                        TLS_Session& params) = 0;

      /**
      * Prohibit resumption of this session. Effectively an erase.
      */
      virtual void prohibit_resumption(const MemoryVector<byte>& session_id) = 0;

      /**
      * Save a session on a best effort basis; the manager may not in
      * fact be able to save the session for whatever reason, this is
      * not an error. Caller cannot assume that calling save followed
      * immediately by find will result in a successful lookup.
      *
      * @param session_id the session identifier
      * @param params to save
      */
      virtual void save(const TLS_Session& params) = 0;

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
      *        to keep in memory at any one time. (If zero, don't cap)
      * @param session_lifetime sessions are expired after this many
      *        seconds have elapsed from initial handshake.
      */
      TLS_Session_Manager_In_Memory(size_t max_sessions = 1000,
                                    size_t session_lifetime = 7200) :
         max_sessions(max_sessions),
         session_lifetime(session_lifetime)
            {}

      bool find(const MemoryVector<byte>& session_id,
                TLS_Session& params);

      bool find(const std::string& hostname, u16bit port,
                TLS_Session& params);

      void prohibit_resumption(const MemoryVector<byte>& session_id);

      void save(const TLS_Session& session_data);

   private:
      size_t max_sessions, session_lifetime;
      std::map<std::string, TLS_Session> sessions;
   };

}

#endif
