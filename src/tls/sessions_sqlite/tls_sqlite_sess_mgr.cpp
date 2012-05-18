/*
* SQLite TLS Session Manager
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_sqlite_sess_mgr.h>
#include <botan/internal/assert.h>
#include <botan/lookup.h>
#include <botan/hex.h>
#include <botan/loadstor.h>
#include <memory>
#include <chrono>

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
            throw std::runtime_error("sqlite3_prepare failed " + base_sql +
                                     ", code " + std::to_string(rc));
         }

      void bind(int column, const std::string& val)
         {
         int rc = sqlite3_bind_text(m_stmt, column, val.c_str(), -1, SQLITE_TRANSIENT);
         if(rc != SQLITE_OK)
            throw std::runtime_error("sqlite3_bind_text failed, code " + std::to_string(rc));
         }

      void bind(int column, int val)
         {
         int rc = sqlite3_bind_int(m_stmt, column, val);
         if(rc != SQLITE_OK)
            throw std::runtime_error("sqlite3_bind_int failed, code " + std::to_string(rc));
         }

      void bind(int column, std::chrono::system_clock::time_point time)
         {
         const int timeval = std::chrono::duration_cast<std::chrono::seconds>(time.time_since_epoch()).count();
         bind(column, timeval);
         }

      void bind(int column, const std::vector<byte>& val)
         {
         int rc = sqlite3_bind_blob(m_stmt, column, &val[0], val.size(), SQLITE_TRANSIENT);
         if(rc != SQLITE_OK)
            throw std::runtime_error("sqlite3_bind_text failed, code " + std::to_string(rc));
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

size_t row_count(sqlite3* db, const std::string& table_name)
   {
   sqlite3_statement stmt(db, "select count(*) from " + table_name);

   if(stmt.step() == SQLITE_ROW)
      return stmt.get_size_t(0);
   else
      throw std::runtime_error("Querying size of table " + table_name + " failed");
   }

void create_table(sqlite3* db, const char* table_schema)
   {
   char* errmsg = 0;
   int rc = sqlite3_exec(db, table_schema, 0, 0, &errmsg);

   if(rc != SQLITE_OK)
      {
      const std::string err_msg = errmsg;
      sqlite3_free(errmsg);
      sqlite3_close(db);
      throw std::runtime_error("sqlite3_exec for table failed - " + err_msg);
      }
   }


SymmetricKey derive_key(const std::string& passphrase,
                        const byte salt[],
                        size_t salt_len,
                        size_t iterations,
                        size_t& check_val)
   {
   std::unique_ptr<PBKDF> pbkdf(get_pbkdf("PBKDF2(SHA-512)"));

   std::vector<byte> x = pbkdf->derive_key(32 + 3,
                                            passphrase,
                                            salt, salt_len,
                                            iterations).bits_of();

   check_val = make_u32bit(0, x[0], x[1], x[2]);
   return SymmetricKey(&x[3], x.size() - 3);
   }

}

Session_Manager_SQLite::Session_Manager_SQLite(const std::string& passphrase,
                                               RandomNumberGenerator& rng,
                                               const std::string& db_filename,
                                               size_t max_sessions,
                                               std::chrono::seconds session_lifetime) :
   m_rng(rng),
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

   create_table(m_db,
                "create table if not exists tls_sessions "
                "("
                "session_id TEXT PRIMARY KEY, "
                "session_start INTEGER, "
                "hostname TEXT, "
                "hostport INTEGER, "
                "session BLOB"
                ")");

   create_table(m_db,
                "create table if not exists tls_sessions_metadata "
                "("
                "passphrase_salt BLOB, "
                "passphrase_iterations INTEGER, "
                "passphrase_check INTEGER "
                ")");

   const size_t salts = row_count(m_db, "tls_sessions_metadata");

   if(salts == 1)
      {
      // existing db
      sqlite3_statement stmt(m_db, "select * from tls_sessions_metadata");

      int rc = stmt.step();
      if(rc == SQLITE_ROW)
         {
         std::pair<const byte*, size_t> salt = stmt.get_blob(0);
         const size_t iterations = stmt.get_size_t(1);
         const size_t check_val_db = stmt.get_size_t(2);

         size_t check_val_created;
         m_session_key = derive_key(passphrase,
                                    salt.first,
                                    salt.second,
                                    iterations,
                                    check_val_created);

         if(check_val_created != check_val_db)
            throw std::runtime_error("Session database password not valid");
         }
      }
   else
      {
      // maybe just zap the salts + sessions tables in this case?
      if(salts != 0)
         throw std::runtime_error("Seemingly corrupted database, multiple salts found");

      // new database case

      std::vector<byte> salt = rng.random_vec(16);
      const size_t iterations = 64 * 1024;
      size_t check_val = 0;

      m_session_key = derive_key(passphrase, &salt[0], salt.size(),
                                 iterations, check_val);

      sqlite3_statement stmt(m_db, "insert into tls_sessions_metadata"
                                   " values(?1, ?2, ?3)");

      stmt.bind(1, salt);
      stmt.bind(2, iterations);
      stmt.bind(3, check_val);

      stmt.spin();
      }
   }

Session_Manager_SQLite::~Session_Manager_SQLite()
   {
   sqlite3_close(m_db);
   }

bool Session_Manager_SQLite::load_from_session_id(const std::vector<byte>& session_id,
                                                  Session& session)
   {
   sqlite3_statement stmt(m_db, "select session from tls_sessions where session_id = ?1");

   stmt.bind(1, hex_encode(session_id));

   int rc = stmt.step();

   while(rc == SQLITE_ROW)
      {
      std::pair<const byte*, size_t> blob = stmt.get_blob(0);

      try
         {
         session = Session::decrypt(blob.first, blob.second, m_session_key);
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
   sqlite3_statement stmt(m_db, "select session from tls_sessions"
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
         session = Session::decrypt(blob.first, blob.second, m_session_key);
         return true;
         }
      catch(...)
         {
         }

      rc = stmt.step();
      }

   return false;
   }

void Session_Manager_SQLite::remove_entry(const std::vector<byte>& session_id)
   {
   sqlite3_statement stmt(m_db, "delete from tls_sessions where session_id = ?1");

   stmt.bind(1, hex_encode(session_id));

   stmt.spin();
   }

void Session_Manager_SQLite::save(const Session& session)
   {
   sqlite3_statement stmt(m_db, "insert or replace into tls_sessions"
                                " values(?1, ?2, ?3, ?4, ?5)");

   stmt.bind(1, hex_encode(session.session_id()));
   stmt.bind(2, session.start_time());
   stmt.bind(3, session.sni_hostname());
   stmt.bind(4, 0);
   stmt.bind(5, session.encrypt(m_session_key, m_rng));

   stmt.spin();

   prune_session_cache();
   }

void Session_Manager_SQLite::prune_session_cache()
   {
   sqlite3_statement remove_expired(m_db, "delete from tls_sessions where session_start <= ?1");

   remove_expired.bind(1, std::chrono::system_clock::now() - m_session_lifetime);

   remove_expired.spin();

   const size_t sessions = row_count(m_db, "tls_sessions");

   if(sessions > m_max_sessions)
      {
      sqlite3_statement remove_some(m_db, "delete from tls_sessions where session_id in "
                                          "(select session_id from tls_sessions limit ?1)");

      remove_some.bind(1, sessions - m_max_sessions);
      remove_some.spin();
      }
   }

}

}
