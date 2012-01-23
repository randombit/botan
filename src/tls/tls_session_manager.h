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

namespace TLS {

/**
* Session_Manager is an interface to systems which can save
* session parameters for supporting session resumption.
*
* Saving sessions is done on a best-effort basis; an implementation is
* allowed to drop sessions due to space constraints.
*
* Implementations should strive to be thread safe
*/
class BOTAN_DLL Session_Manager
   {
   public:
      /**
      * Try to load a saved session (server side)
      * @param session_id the session identifier we are trying to resume
      * @param session will be set to the saved session data (if found),
               or not modified if not found
      * @return true if session was modified
      */
      virtual bool load_from_session_id(const MemoryRegion<byte>& session_id,
                                        Session& session) = 0;

      /**
      * Try to load a saved session (client side)
      * @param hostname of the host we are connecting to
      * @param port the port number if we know it, or 0 if unknown
      * @param session will be set to the saved session data (if found),
               or not modified if not found
      * @return true if session was modified
      */
      virtual bool load_from_host_info(const std::string& hostname, u16bit port,
                                       Session& session) = 0;

      /**
      * Remove this session id from the cache, if it exists
      */
      virtual void remove_entry(const MemoryRegion<byte>& session_id) = 0;

      /**
      * Save a session on a best effort basis; the manager may not in
      * fact be able to save the session for whatever reason; this is
      * not an error. Caller cannot assume that calling save followed
      * immediately by load_from_* will result in a successful lookup.
      *
      * @param session to save
      */
      virtual void save(const Session& session) = 0;

      virtual ~Session_Manager() {}
   };

/**
* A simple implementation of Session_Manager that just saves
* values in memory, with no persistance abilities
*
* @todo add locking
*/
class BOTAN_DLL Session_Manager_In_Memory : public Session_Manager
   {
   public:
      /**
      * @param max_sessions a hint on the maximum number of sessions
      *        to keep in memory at any one time. (If zero, don't cap)
      * @param session_lifetime sessions are expired after this many
      *        seconds have elapsed from initial handshake.
      */
      Session_Manager_In_Memory(size_t max_sessions = 1000,
                                    size_t session_lifetime = 7200) :
         max_sessions(max_sessions),
         session_lifetime(session_lifetime)
            {}

      bool load_from_session_id(const MemoryRegion<byte>& session_id,
                                Session& session);

      bool load_from_host_info(const std::string& hostname, u16bit port,
                               Session& session);

      void remove_entry(const MemoryRegion<byte>& session_id);

      void save(const Session& session_data);

   private:
      bool load_from_session_str(const std::string& session_str,
                                 Session& session);

      size_t max_sessions, session_lifetime;

      std::map<std::string, Session> sessions; // hex(session_id) -> session
      std::map<std::string, std::string> host_sessions;
   };

}

}

#endif
