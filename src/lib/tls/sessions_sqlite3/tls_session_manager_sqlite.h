/*
* SQLite3 TLS Session Manager
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_SQLITE3_SESSION_MANAGER_H_
#define BOTAN_TLS_SQLITE3_SESSION_MANAGER_H_

#include <botan/tls_session_manager_sql.h>

namespace Botan {

class RandomNumberGenerator;

namespace TLS {

/**
* An implementation of Session_Manager that saves values in a SQLite3
* database file, with the session data encrypted using a passphrase.
*
* @warning For clients, the hostnames associated with the saved
* sessions are stored in the database in plaintext. This may be a
* serious privacy risk in some situations.
*/
class BOTAN_PUBLIC_API(2,0)
Session_Manager_SQLite final : public Session_Manager_SQL
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
};

}

}

#endif
