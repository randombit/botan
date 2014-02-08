/*
* SQLite3 TLS Session Manager
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_SQLITE3_SESSION_MANAGER_H__
#define BOTAN_TLS_SQLITE3_SESSION_MANAGER_H__

#include <botan/tls_session_manager.h>
#include <botan/rng.h>

namespace Botan {

class sqlite3_database;

namespace TLS {

/**
* An implementation of Session_Manager that saves values in a SQLite3
* database file, with the session data encrypted using a passphrase.
*
* @warning For clients, the hostnames associated with the saved
* sessions are stored in the database in plaintext. This may be a
* serious privacy risk in some situations.
*/
class BOTAN_DLL Session_Manager_SQLite : public Session_Manager
   {
   public:
      /**
      * @param passphrase used to encrypt the session data
      * @param rng a random number generator
      * @param db_filename filename of the SQLite database file.
               The table names tls_sessions and tls_sessions_metadata
               will be used
      * @param max_sessions a hint on the maximum number of sessions
      *        to keep in memory at any one time. (If zero, don't cap)
      * @param session_lifetime sessions are expired after this many
      *        seconds have elapsed from initial handshake.
      */
      Session_Manager_SQLite(const std::string& passphrase,
                             RandomNumberGenerator& rng,
                             const std::string& db_filename,
                             size_t max_sessions = 1000,
                             std::chrono::seconds session_lifetime = std::chrono::seconds(7200));

      ~Session_Manager_SQLite();

      bool load_from_session_id(const std::vector<byte>& session_id,
                                Session& session) override;

      bool load_from_server_info(const Server_Information& info,
                                 Session& session) override;

      void remove_entry(const std::vector<byte>& session_id) override;

      void save(const Session& session_data) override;

      std::chrono::seconds session_lifetime() const override
         { return m_session_lifetime; }

   private:
      Session_Manager_SQLite(const Session_Manager_SQLite&);
      Session_Manager_SQLite& operator=(const Session_Manager_SQLite&);

      void prune_session_cache();

      SymmetricKey m_session_key;
      RandomNumberGenerator& m_rng;
      size_t m_max_sessions;
      std::chrono::seconds m_session_lifetime;
      sqlite3_database* m_db;
   };

}

}

#endif
