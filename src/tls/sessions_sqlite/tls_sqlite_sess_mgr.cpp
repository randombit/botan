/*
* SQLite TLS Session Manager
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_sqlite_sess_mgr.h>
#include <botan/internal/assert.h>
#include <botan/hex.h>
#include <sqlite3.h>

namespace Botan {

namespace TLS {

namespace {

class sqlite3_statment
   {
   public:
      sqlite3_statment(sqlite3* db, const std::string& base_sql)
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

      int step()
         {
         return sqlite3_step(m_stmt);
         }

      sqlite3_stmt* stmt() { return m_stmt; }

      ~sqlite3_statment() { sqlite3_finalize(m_stmt); }
   private:
      sqlite3_stmt* m_stmt;
   };

}

Session_Manager_SQLite::Session_Manager_SQLite(const std::string& db_filename,
                                               const std::string& table_name,
                                               size_t max_sessions,
                                               size_t session_lifetime) :
   m_table_name(table_name)
   {
   int rc = sqlite3_open(db_filename.c_str(), &m_db);
   if(rc)
      {
      const std::string err_msg = sqlite3_errmsg(m_db);
      sqlite3_close(m_db);
      throw std::runtime_error("sqlite3_open failed - " + err_msg);
      }

   const std::string table_sql =
      "create table if not exists " +
      m_table_name + "(" +
      "hostname TEXT, "
      "hostport INTEGER, "
      "session_start INTEGER, "
      "session_id TEXT UNIQUE, "
      "session TEXT"
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
   sqlite3_statment stmt(m_db, "select session from " + m_table_name + " where session_id = ?1");

   stmt.bind(1, hex_encode(session_id));

   int rc = stmt.step();

   while(rc == SQLITE_ROW)
      {
      BOTAN_ASSERT(sqlite3_column_type(stmt.stmt(), 0) == SQLITE_BLOB,
                   "Return value is a text");

      const void* session_blob = sqlite3_column_blob(stmt.stmt(), 0);
      const int session_blob_size = sqlite3_column_bytes(stmt.stmt(), 0);

      try
         {
         session = Session(static_cast<const byte*>(session_blob), session_blob_size);
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
   sqlite3_statment stmt(m_db, "select session from " + m_table_name +
                         " where hostname = ?1 and hostport = ?2"
                         " order by session_start limit 1");

   stmt.bind(1, hostname);
   stmt.bind(2, port);

   int rc = stmt.step();

   while(rc == SQLITE_ROW)
      {
      BOTAN_ASSERT(sqlite3_column_type(stmt.stmt(), 0) == SQLITE_BLOB,
                   "Return value is a blob");

      const void* session_blob = sqlite3_column_blob(stmt.stmt(), 0);
      const int session_blob_size = sqlite3_column_bytes(stmt.stmt(), 0);

      try
         {
         session = Session(static_cast<const byte*>(session_blob), session_blob_size);
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
   sqlite3_statment stmt(m_db, "delete from " + m_table_name + " where session_id = ?1");

   stmt.bind(1, hex_encode(session_id));

   while(stmt.step() == SQLITE_ROW)
      ;
   }

void Session_Manager_SQLite::save(const Session& session)
   {
   sqlite3_statment stmt(m_db, "insert into " + m_table_name + " values(?1, ?2, ?3, ?4, ?5)");

   stmt.bind(1, session.sni_hostname());
   stmt.bind(2, 0);
   stmt.bind(3, session.start_time());
   stmt.bind(4, hex_encode(session.session_id()));
   stmt.bind(5, session.DER_encode());

   while(stmt.step() == SQLITE_ROW)
      ;
   }

}

}
