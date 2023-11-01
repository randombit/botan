/*
* SQLite wrapper
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sqlite3.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/fmt.h>
#include <sqlite3.h>

namespace Botan {

Sqlite3_Database::Sqlite3_Database(std::string_view db_filename, std::optional<int> sqlite_open_flags) {
   // SQLITE_OPEN_FULLMUTEX ensures that the database object can be used
   // concurrently from multiple threads.
   const int open_flags =
      sqlite_open_flags.value_or(SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
   int rc = ::sqlite3_open_v2(std::string(db_filename).c_str(), &m_db, open_flags, nullptr);

   if(rc) [[unlikely]] {
      const std::string err_msg = ::sqlite3_errmsg(m_db);
      ::sqlite3_close(m_db);
      m_db = nullptr;
      throw SQL_DB_Error("sqlite3_open failed - " + err_msg);
   }
}

Sqlite3_Database::~Sqlite3_Database() {
   if(m_db) [[likely]] {
      ::sqlite3_close(m_db);
   }
   m_db = nullptr;
}

std::shared_ptr<SQL_Database::Statement> Sqlite3_Database::new_statement(std::string_view base_sql) const {
   return std::make_shared<Sqlite3_Statement>(m_db, base_sql);
}

size_t Sqlite3_Database::row_count(std::string_view table_name) {
   auto stmt = new_statement(fmt("select count(*) from {}", table_name));

   if(stmt->step()) {
      return stmt->get_size_t(0);
   } else {
      throw SQL_DB_Error(fmt("Querying size of table '{}' failed", table_name));
   }
}

void Sqlite3_Database::create_table(std::string_view table_schema) {
   char* errmsg = nullptr;
   int rc = ::sqlite3_exec(m_db, std::string(table_schema).c_str(), nullptr, nullptr, &errmsg);

   if(rc != SQLITE_OK) {
      const std::string err_msg = errmsg;
      ::sqlite3_free(errmsg);
      ::sqlite3_close(m_db);
      m_db = nullptr;
      throw SQL_DB_Error("sqlite3_exec for table failed - " + err_msg);
   }
}

size_t Sqlite3_Database::rows_changed_by_last_statement() {
   const auto result = ::sqlite3_changes64(m_db);
   BOTAN_ASSERT_NOMSG(result >= 0);
   return static_cast<size_t>(result);
}

bool Sqlite3_Database::is_threadsafe() const {
   const int flag = sqlite3_threadsafe();

   // `flag` can have three values:
   //
   // 0 - single threaded:  no locking is done inside the SQLite code
   // 1 - serialized:       all SQLite database features can be used safely
   //                       from multiple threads
   // 2 - reduced locking:  application must ensure not to use a single
   //                       database connection across threads
   //
   // https://www.sqlite.org/c3ref/threadsafe.html

   // When opening the database connection we explicitly request
   // SQLITE_OPEN_FULLMUTEX to ensure restrictive locking in SQLite.
   return flag >= 1;
}

Sqlite3_Database::Sqlite3_Statement::Sqlite3_Statement(sqlite3* db, std::string_view base_sql) {
   int rc = ::sqlite3_prepare_v2(db, base_sql.data(), static_cast<int>(base_sql.size()), &m_stmt, nullptr);

   if(rc != SQLITE_OK) {
      throw SQL_DB_Error(fmt("sqlite3_prepare failed on '{}' with err {}", base_sql, rc), rc);
   }
}

void Sqlite3_Database::Sqlite3_Statement::bind(int column, std::string_view val) {
   int rc = ::sqlite3_bind_text64(m_stmt, column, val.data(), val.size(), SQLITE_TRANSIENT, SQLITE_UTF8);
   if(rc != SQLITE_OK) {
      throw SQL_DB_Error("sqlite3_bind_text failed", rc);
   }
}

void Sqlite3_Database::Sqlite3_Statement::bind(int column, size_t val) {
   int rc = ::sqlite3_bind_int64(m_stmt, column, val);
   if(rc != SQLITE_OK) {
      throw SQL_DB_Error("sqlite3_bind_int failed", rc);
   }
}

void Sqlite3_Database::Sqlite3_Statement::bind(int column, std::chrono::system_clock::time_point time) {
   const uint64_t timeval = std::chrono::duration_cast<std::chrono::seconds>(time.time_since_epoch()).count();
   bind(column, static_cast<size_t>(timeval));
}

void Sqlite3_Database::Sqlite3_Statement::bind(int column, const std::vector<uint8_t>& val) {
   int rc = ::sqlite3_bind_blob64(m_stmt, column, val.data(), val.size(), SQLITE_TRANSIENT);
   if(rc != SQLITE_OK) {
      throw SQL_DB_Error("sqlite3_bind_text failed", rc);
   }
}

void Sqlite3_Database::Sqlite3_Statement::bind(int column, const uint8_t* p, size_t len) {
   int rc = ::sqlite3_bind_blob64(m_stmt, column, p, len, SQLITE_TRANSIENT);
   if(rc != SQLITE_OK) {
      throw SQL_DB_Error("sqlite3_bind_text failed", rc);
   }
}

std::pair<const uint8_t*, size_t> Sqlite3_Database::Sqlite3_Statement::get_blob(int column) {
   const auto column_type = ::sqlite3_column_type(m_stmt, column);
   if(column_type == SQLITE_NULL) {
      return {nullptr, 0};
   }

   BOTAN_ASSERT(column_type == SQLITE_BLOB, "Return value is a blob");

   const void* session_blob = ::sqlite3_column_blob(m_stmt, column);
   const int session_blob_size = ::sqlite3_column_bytes(m_stmt, column);

   BOTAN_ASSERT(session_blob_size >= 0, "Blob size is non-negative");

   return std::make_pair(static_cast<const uint8_t*>(session_blob), static_cast<size_t>(session_blob_size));
}

std::string Sqlite3_Database::Sqlite3_Statement::get_str(int column) {
   BOTAN_ASSERT(::sqlite3_column_type(m_stmt, column) == SQLITE_TEXT, "Return value is text");

   const unsigned char* str = ::sqlite3_column_text(m_stmt, column);

   return std::string(cast_uint8_ptr_to_char(str));
}

size_t Sqlite3_Database::Sqlite3_Statement::get_size_t(int column) {
   BOTAN_ASSERT(::sqlite3_column_type(m_stmt, column) == SQLITE_INTEGER, "Return count is an integer");

   const size_t sessions_int = ::sqlite3_column_int64(m_stmt, column);

   return sessions_int;
}

size_t Sqlite3_Database::Sqlite3_Statement::spin() {
   size_t steps = 0;
   while(step()) {
      ++steps;
   }

   return steps;
}

bool Sqlite3_Database::Sqlite3_Statement::step() {
   return (::sqlite3_step(m_stmt) == SQLITE_ROW);
}

Sqlite3_Database::Sqlite3_Statement::~Sqlite3_Statement() {
   ::sqlite3_finalize(m_stmt);
}

}  // namespace Botan
