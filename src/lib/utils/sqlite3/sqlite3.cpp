/*
* SQLite wrapper
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sqlite3.h>
#include <stdexcept>
#include <sqlite3.h>

namespace Botan {

Sqlite3_Database::Sqlite3_Database(const std::string& db_filename)
   {
   int rc = ::sqlite3_open(db_filename.c_str(), &m_db);

   if(rc)
      {
      const std::string err_msg = ::sqlite3_errmsg(m_db);
      ::sqlite3_close(m_db);
      m_db = nullptr;
      throw std::runtime_error("sqlite3_open failed - " + err_msg);
      }
   }

Sqlite3_Database::~Sqlite3_Database()
   {
   if(m_db)
      ::sqlite3_close(m_db);
   m_db = nullptr;
   }

std::shared_ptr<SQL_Database::Statement> Sqlite3_Database::new_statement(const std::string& base_sql) const
   {
   return std::make_shared<Sqlite3_Statement>(m_db, base_sql);
   }

size_t Sqlite3_Database::row_count(const std::string& table_name)
   {
   auto stmt = new_statement("select count(*) from " + table_name);

   if(stmt->step())
      return stmt->get_size_t(0);
   else
      throw std::runtime_error("Querying size of table " + table_name + " failed");
   }

void Sqlite3_Database::create_table(const std::string& table_schema)
   {
   char* errmsg = nullptr;
   int rc = ::sqlite3_exec(m_db, table_schema.c_str(), nullptr, nullptr, &errmsg);

   if(rc != SQLITE_OK)
      {
      const std::string err_msg = errmsg;
      ::sqlite3_free(errmsg);
      ::sqlite3_close(m_db);
      m_db = nullptr;
      throw std::runtime_error("sqlite3_exec for table failed - " + err_msg);
      }
   }

Sqlite3_Database::Sqlite3_Statement::Sqlite3_Statement(sqlite3* db, const std::string& base_sql)
   {
   int rc = ::sqlite3_prepare_v2(db, base_sql.c_str(), -1, &m_stmt, nullptr);

   if(rc != SQLITE_OK)
      throw std::runtime_error("sqlite3_prepare failed " + base_sql +
                               ", code " + std::to_string(rc));
   }

void Sqlite3_Database::Sqlite3_Statement::bind(int column, const std::string& val)
   {
   int rc = ::sqlite3_bind_text(m_stmt, column, val.c_str(), -1, SQLITE_TRANSIENT);
   if(rc != SQLITE_OK)
      throw std::runtime_error("sqlite3_bind_text failed, code " + std::to_string(rc));
   }

void Sqlite3_Database::Sqlite3_Statement::bind(int column, size_t val)
   {
   if(val != static_cast<size_t>(static_cast<int>(val))) // is this legit?
      throw std::runtime_error("sqlite3 cannot store " + std::to_string(val) + " without truncation");
   int rc = ::sqlite3_bind_int(m_stmt, column, val);
   if(rc != SQLITE_OK)
      throw std::runtime_error("sqlite3_bind_int failed, code " + std::to_string(rc));
   }

void Sqlite3_Database::Sqlite3_Statement::bind(int column, std::chrono::system_clock::time_point time)
   {
   const int timeval = std::chrono::duration_cast<std::chrono::seconds>(time.time_since_epoch()).count();
   bind(column, timeval);
   }

void Sqlite3_Database::Sqlite3_Statement::bind(int column, const std::vector<byte>& val)
   {
   int rc = ::sqlite3_bind_blob(m_stmt, column, val.data(), val.size(), SQLITE_TRANSIENT);
   if(rc != SQLITE_OK)
      throw std::runtime_error("sqlite3_bind_text failed, code " + std::to_string(rc));
   }

std::pair<const byte*, size_t> Sqlite3_Database::Sqlite3_Statement::get_blob(int column)
   {
   BOTAN_ASSERT(::sqlite3_column_type(m_stmt, 0) == SQLITE_BLOB,
                "Return value is a blob");

   const void* session_blob = ::sqlite3_column_blob(m_stmt, column);
   const int session_blob_size = ::sqlite3_column_bytes(m_stmt, column);

   BOTAN_ASSERT(session_blob_size >= 0, "Blob size is non-negative");

   return std::make_pair(static_cast<const byte*>(session_blob),
                         static_cast<size_t>(session_blob_size));
   }

size_t Sqlite3_Database::Sqlite3_Statement::get_size_t(int column)
   {
   BOTAN_ASSERT(::sqlite3_column_type(m_stmt, column) == SQLITE_INTEGER,
                "Return count is an integer");

   const int sessions_int = ::sqlite3_column_int(m_stmt, column);

   BOTAN_ASSERT(sessions_int >= 0, "Expected size_t is non-negative");

   return static_cast<size_t>(sessions_int);
   }

void Sqlite3_Database::Sqlite3_Statement::spin()
   {
   while(step()) {}
   }

bool Sqlite3_Database::Sqlite3_Statement::step()
   {
   return (::sqlite3_step(m_stmt) == SQLITE_ROW);
   }

Sqlite3_Database::Sqlite3_Statement::~Sqlite3_Statement()
   {
   ::sqlite3_finalize(m_stmt);
   }

}
