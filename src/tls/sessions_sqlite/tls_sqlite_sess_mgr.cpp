/*
* SQLite TLS Session Manager
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_sqlite_sess_mgr.h>
#include <botan/internal/assert.h>
#include <botan/hex.h>
#include <botan/time.h>
#include <sqlite3.h>

namespace Botan {

namespace TLS {

namespace {

class sqlite3_statement
   {
   public:
      sqlite3_statement(sqlite3* db, const std::string& base_sql)
         {
         int rc = sqlite3_prepare_v2(db, base_sql.c_str(), -1, &m_stmt, 0);

         if(rc != SQLITE_OK)
            throw std::runtime_error("sqlite3_prepare failed " + base_sql + ", code " + to_string(rc));
         }

      void bind(int column, const std::string& val)
         {
         int rc = sqlite3_bind_text(m_stmt, column, val.c_str(), -1, SQLITE_TRANSIENT);
         if(rc != SQLITE_OK)
            throw std::runtime_error("sqlite3_bind_text failed, code " + to_string(rc));
         }

      void bind(int column, int val)
         {
         int rc = sqlite3_bind_int(m_stmt, column, val);
         if(rc != SQLITE_OK)
            throw std::runtime_error("sqlite3_bind_int failed, code " + to_string(rc));
         }

      void bind(int column, const MemoryRegion<byte>& val)
         {
         int rc = sqlite3_bind_blob(m_stmt, column, &val[0], val.size(), SQLITE_TRANSIENT);
         if(rc != SQLITE_OK)
            throw std::runtime_error("sqlite3_bind_text failed, code " + to_string(rc));
         }

      std::pair<const byte*, size_t> get_blob(int column)
         {
         BOTAN_ASSERT(sqlite3_column_type(m_stmt, 0) == SQLITE_BLOB,
                      "Return value is a blob");

         const void* session_blob = sqlite3_column_blob(m_stmt, column);
         const int session_blob_size = sqlite3_column_bytes(m_stmt, column);

         BOTAN_ASSERT(session_blob_size >= 0, "Blob size is non-negative");

         return std::make_pair(static_cast<const byte*>(session_blob),
                               static_cast<size_t>(session_blob_size));
         }

      size_t get_size_t(int column)
         {
         BOTAN_ASSERT(sqlite3_column_type(m_stmt, column) == SQLITE_INTEGER,
                      "Return count is an integer");

         const int sessions_int = sqlite3_column_int(m_stmt, column);

         BOTAN_ASSERT(sessions_int >= 0, "Expected size_t is non-negative");

         return static_cast<size_t>(sessions_int);
         }

      void spin()
         {
         while(sqlite3_step(m_stmt) == SQLITE_ROW)
            {}
         }

      int step()
         {
         return sqlite3_step(m_stmt);
         }

      sqlite3_stmt* stmt() { return m_stmt; }

      ~sqlite3_statement() { sqlite3_finalize(m_stmt); }
   private:
      sqlite3_stmt* m_stmt;
   };

}

Session_Manager_SQLite::Session_Manager_SQLite(const std::string& db_filename,
                                               const std::string& table_name,
                                               size_t max_sessions,
                                               size_t session_lifetime) :
   m_table_name(table_name),
   m_max_sessions(max_sessions),
   m_session_lifetime(session_lifetime)
   {
   int rc = sqlite3_open(db_filename.c_str(), &m_db);
   if(rc)
      {
      const std::string err_msg = sqlite3_errmsg(m_db);
      sqlite3_close(m_db);
      throw std::runtime_error("sqlite3_open failed - " + err_msg);
      }

   const std::string table_sql =
      "create table if not exists " + m_table_name +
      "("
      "session_id TEXT PRIMARY KEY, "
      "session_start INTEGER, "
      "hostname TEXT, "
      "hostport INTEGER, "
      "session BLOB"
      ")";

   char* errmsg = 0;
   rc = sqlite3_exec(m_db, table_sql.c_str(), 0, 0, &errmsg);

   if(rc != SQLITE_OK)
      {
      const std::string err_msg = errmsg;
      sqlite3_free(errmsg);
      sqlite3_close(m_db);
      throw std::runtime_error("sqlite3_exec for table failed - " + err_msg);
      }
   }

Session_Manager_SQLite::~Session_Manager_SQLite()
   {
   sqlite3_close(m_db);
   }

bool Session_Manager_SQLite::load_from_session_id(const MemoryRegion<byte>& session_id,
                                                  Session& session)
   {
   sqlite3_statement stmt(m_db, "select session from " + m_table_name + " where session_id = ?1");

   stmt.bind(1, hex_encode(session_id));

   int rc = stmt.step();

   while(rc == SQLITE_ROW)
      {
      std::pair<const byte*, size_t> blob = stmt.get_blob(0);

      try
         {
         session = Session(blob.first, blob.second);
         return true;
         }
      catch(...)
         {
         }

      rc = stmt.step();
      }

   return false;
   }

bool Session_Manager_SQLite::load_from_host_info(const std::string& hostname,
                                                 u16bit port,
                                                 Session& session)
   {
   sqlite3_statement stmt(m_db, "select session from " + m_table_name +
                                " where hostname = ?1 and hostport = ?2"
                                " order by session_start desc");

   stmt.bind(1, hostname);
   stmt.bind(2, port);

   int rc = stmt.step();

   while(rc == SQLITE_ROW)
      {
      std::pair<const byte*, size_t> blob = stmt.get_blob(0);

      try
         {
         session = Session(blob.first, blob.second);
         return true;
         }
      catch(...)
         {
         }

      rc = stmt.step();
      }

   return false;
   }

void Session_Manager_SQLite::remove_entry(const MemoryRegion<byte>& session_id)
   {
   sqlite3_statement stmt(m_db, "delete from " + m_table_name + " where session_id = ?1");

   stmt.bind(1, hex_encode(session_id));

   stmt.spin();
   }

void Session_Manager_SQLite::save(const Session& session)
   {
   sqlite3_statement stmt(m_db, "insert into " + m_table_name + " values(?1, ?2, ?3, ?4, ?5)");

   stmt.bind(1, hex_encode(session.session_id()));
   stmt.bind(2, session.start_time());
   stmt.bind(3, session.sni_hostname());
   stmt.bind(4, 0);
   stmt.bind(5, session.DER_encode());

   stmt.spin();

   prune_session_cache();
   }

void Session_Manager_SQLite::prune_session_cache()
   {
   sqlite3_statement remove_expired(m_db, "delete from " + m_table_name + " where session_start <= ?1");

   remove_expired.bind(1, system_time() - m_session_lifetime);

   remove_expired.spin();

   sqlite3_statement row_count(m_db, "select count(*) from " + m_table_name);

   if(row_count.step() == SQLITE_ROW)
      {
      const size_t sessions = row_count.get_size_t(0);

      if(sessions > m_max_sessions)
         {
         sqlite3_statement remove_some(m_db, "delete from " + m_table_name + " where session_id in "
                                             "(select session_id from " + m_table_name + " limit ?1)");

         remove_some.bind(1, sessions - m_max_sessions);
         remove_some.spin();
         }
      }
   }

}

}
