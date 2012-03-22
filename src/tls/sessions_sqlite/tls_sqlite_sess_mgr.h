/*
* SQLite TLS Session Manager
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef TLS_SQLITE_SESSION_MANAGER_H__
#define TLS_SQLITE_SESSION_MANAGER_H__

#include <botan/tls_session_manager.h>

class sqlite3;

namespace Botan {

namespace TLS {

/**
*/
class BOTAN_DLL Session_Manager_SQLite : public Session_Manager
   {
   public:
      /**
      * @param db_filename filename of the SQLite database file
      * @param table_name names the table to store sessions in
      * @param max_sessions a hint on the maximum number of sessions
      *        to keep in memory at any one time. (If zero, don't cap)
      * @param session_lifetime sessions are expired after this many
      *        seconds have elapsed from initial handshake.
      */
      Session_Manager_SQLite(const std::string& db_filename,
                             const std::string& table_name = "tls_sessions",
                             size_t max_sessions = 1000,
                             size_t session_lifetime = 7200);

      ~Session_Manager_SQLite();

      bool load_from_session_id(const MemoryRegion<byte>& session_id,
                                Session& session);

      bool load_from_host_info(const std::string& hostname, u16bit port,
                               Session& session);

      void remove_entry(const MemoryRegion<byte>& session_id);

      void save(const Session& session_data);
   private:
      Session_Manager_SQLite(const Session_Manager_SQLite&) {}
      Session_Manager_SQLite& operator=(const Session_Manager_SQLite&) { return (*this); }

      void prune_session_cache();

      std::string m_table_name;
      size_t m_max_sessions, m_session_lifetime;
      class sqlite3* m_db;
   };

}

}

#endif
