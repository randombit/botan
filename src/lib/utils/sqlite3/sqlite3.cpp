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
#include <botan/internal/int_utils.h>
#include <sqlite3.h>

namespace Botan {

Sqlite3_Database::Sqlite3_Database(std::string_view db_filename, std::optional<int> sqlite_open_flags) {
   // SQLITE_OPEN_FULLMUTEX ensures that the database object can be used
   // concurrently from multiple threads.
   const int open_flags =
      sqlite_open_flags.value_or(SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
   sqlite3* db = nullptr;
   const int rc = ::sqlite3_open_v2(std::string(db_filename).c_str(), &db, open_flags, nullptr);

   if(rc != 0) [[unlikely]] {
      const std::string err_msg = (db != nullptr) ? ::sqlite3_errmsg(db) : "unknown error";
      ::sqlite3_close_v2(db);
      throw SQL_DB_Error("sqlite3_open failed - " + err_msg);
   }

   m_db = std::shared_ptr<sqlite3>(db, [](sqlite3* p) noexcept { ::sqlite3_close_v2(p); });
}

Sqlite3_Database::~Sqlite3_Database() = default;

std::shared_ptr<SQL_Database::Statement> Sqlite3_Database::new_statement(std::string_view base_sql) const {
   return std::make_shared<Sqlite3_Statement>(m_db, base_sql);
}

std::shared_ptr<SQL_Database::Statement> Sqlite3_Database::upsert(
   std::string_view table, std::initializer_list<std::string_view> columns) const {
   BOTAN_ARG_CHECK(columns.size() > 0, "upsert requires at least one column");

   std::string sql = "INSERT OR REPLACE INTO ";
   sql += table;
   sql += " (";
   bool first = true;
   for(const auto& col : columns) {
      if(!first) {
         sql += ", ";
      }
      sql += col;
      first = false;
   }
   sql += ") VALUES (";
   for(size_t i = 1; i <= columns.size(); ++i) {
      if(i > 1) {
         sql += ", ";
      }
      sql += fmt("?{}", i);
   }
   sql += ")";

   return new_statement(sql);
}

size_t Sqlite3_Database::row_count(std::string_view table_name) {
   auto stmt = new_statement(fmt("select count(*) from {}", table_name));

   if(stmt->step()) {
      return stmt->get_size_t(0);
   } else {
      throw SQL_DB_Error(fmt("Querying size of table '{}' failed", table_name));
   }
}

void Sqlite3_Database::create_table(const Table_Schema& schema) {
   BOTAN_ARG_CHECK(!schema.name().empty(), "create_table requires a table name");
   BOTAN_ARG_CHECK(!schema.columns().empty(), "create_table requires at least one column");

   std::string sql = "CREATE TABLE ";
   if(schema.is_if_not_exists()) {
      sql += "IF NOT EXISTS ";
   }
   sql += schema.name();
   sql += " (";
   bool first = true;
   for(const auto& col : schema.columns()) {
      if(!first) {
         sql += ", ";
      }
      sql += col.name();
      sql += ' ';
      switch(col.type()) {
         case Column_Type::Blob:
            sql += "BLOB";
            break;
         case Column_Type::String:
            sql += "TEXT";
            break;
         case Column_Type::Integer:
            sql += "INTEGER";
            break;
      }
      if(col.is_primary_key()) {
         sql += " PRIMARY KEY";
      }
      if(col.is_unique()) {
         sql += " UNIQUE";
      }
      if(col.is_not_null()) {
         sql += " NOT NULL";
      }
      first = false;
   }
   sql += ")";

   char* errmsg = nullptr;
   const int rc = ::sqlite3_exec(m_db.get(), sql.c_str(), nullptr, nullptr, &errmsg);

   if(rc != SQLITE_OK) {
      const std::string err_msg = (errmsg != nullptr) ? errmsg : "unknown error";
      ::sqlite3_free(errmsg);
      throw SQL_DB_Error("sqlite3_exec for create_table failed - " + err_msg, rc);
   }
}

size_t Sqlite3_Database::rows_changed_by_last_statement() {
   const auto result = ::sqlite3_changes64(m_db.get());
   BOTAN_ASSERT_NOMSG(result >= 0);
   return static_cast<size_t>(result);
}

bool Sqlite3_Database::is_threadsafe() const {
   // sqlite3_db_mutex() returns the connection's mutex if the connection is in
   // serialized mode, and nullptr otherwise. This reflects both the compile-time
   // SQLITE_THREADSAFE setting and the per-connection SQLITE_OPEN_(FULL|NO)MUTEX
   // open flags actually used.
   //
   // https://www.sqlite.org/c3ref/db_mutex.html
   return ::sqlite3_db_mutex(m_db.get()) != nullptr;
}

Sqlite3_Database::Sqlite3_Statement::Sqlite3_Statement(std::shared_ptr<sqlite3> db, std::string_view base_sql) :
      m_db(std::move(db)), m_stmt{} {
   const int rc =
      ::sqlite3_prepare_v2(m_db.get(), base_sql.data(), static_cast<int>(base_sql.size()), &m_stmt, nullptr);

   if(rc != SQLITE_OK) {
      throw SQL_DB_Error(fmt("sqlite3_prepare failed on '{}' with err {}", base_sql, rc), rc);
   }
}

void Sqlite3_Database::Sqlite3_Statement::bind(int column, std::string_view val) {
   if(val.data() == nullptr) {
      bind_null(column);
      return;
   }
   const int rc = ::sqlite3_bind_text64(m_stmt, column, val.data(), val.size(), SQLITE_TRANSIENT, SQLITE_UTF8);
   if(rc != SQLITE_OK) {
      throw SQL_DB_Error("sqlite3_bind_text failed", rc);
   }
}

void Sqlite3_Database::Sqlite3_Statement::bind(int column, size_t val) {
   const int rc = ::sqlite3_bind_int64(m_stmt, column, val);
   if(rc != SQLITE_OK) {
      throw SQL_DB_Error("sqlite3_bind_int failed", rc);
   }
}

void Sqlite3_Database::Sqlite3_Statement::bind(int column, std::chrono::system_clock::time_point time) {
   const uint64_t timeval = std::chrono::duration_cast<std::chrono::seconds>(time.time_since_epoch()).count();
   bind(column, static_cast<size_t>(timeval));
}

void Sqlite3_Database::Sqlite3_Statement::bind(int column, const std::vector<uint8_t>& val) {
   bind(column, val.data(), val.size());
}

void Sqlite3_Database::Sqlite3_Statement::bind(int column, const uint8_t* p, size_t len) {
   if(p == nullptr) {
      bind_null(column);
      return;
   }
   const int rc = ::sqlite3_bind_blob64(m_stmt, column, p, len, SQLITE_TRANSIENT);
   if(rc != SQLITE_OK) {
      throw SQL_DB_Error("sqlite3_bind_blob failed", rc);
   }
}

void Sqlite3_Database::Sqlite3_Statement::bind_null(int column) {
   const int rc = ::sqlite3_bind_null(m_stmt, column);
   if(rc != SQLITE_OK) {
      throw SQL_DB_Error("sqlite3_bind_null failed", rc);
   }
}

std::span<const uint8_t> Sqlite3_Database::Sqlite3_Statement::get_blob(int column) {
   const auto column_type = ::sqlite3_column_type(m_stmt, column);
   if(column_type == SQLITE_NULL) {
      return {};
   }

   BOTAN_ASSERT(column_type == SQLITE_BLOB, "Return value is a blob");

   const void* session_blob = ::sqlite3_column_blob(m_stmt, column);
   const int session_blob_size = ::sqlite3_column_bytes(m_stmt, column);

   BOTAN_ASSERT(session_blob_size >= 0, "Blob size is non-negative");

   return {static_cast<const uint8_t*>(session_blob), static_cast<size_t>(session_blob_size)};
}

std::optional<std::string> Sqlite3_Database::Sqlite3_Statement::get_str(int column) {
   const auto column_type = ::sqlite3_column_type(m_stmt, column);
   if(column_type == SQLITE_NULL) {
      return std::nullopt;
   }

   BOTAN_ASSERT(column_type == SQLITE_TEXT, "Return value is text");

   const unsigned char* str = ::sqlite3_column_text(m_stmt, column);
   const int len = ::sqlite3_column_bytes(m_stmt, column);
   BOTAN_ASSERT(len >= 0, "Text length is non-negative");

   return std::string(cast_uint8_ptr_to_char(str), static_cast<size_t>(len));
}

size_t Sqlite3_Database::Sqlite3_Statement::get_size_t(int column) {
   BOTAN_ASSERT(::sqlite3_column_type(m_stmt, column) == SQLITE_INTEGER, "Return count is an integer");

   return checked_cast_to<size_t>(::sqlite3_column_int64(m_stmt, column));
}

size_t Sqlite3_Database::Sqlite3_Statement::spin() {
   size_t steps = 0;
   while(step()) {
      ++steps;
   }

   return steps;
}

bool Sqlite3_Database::Sqlite3_Statement::step() {
   const int rc = ::sqlite3_step(m_stmt);
   if(rc == SQLITE_ROW) {
      return true;
   }
   if(rc == SQLITE_DONE) {
      return false;
   }
   throw SQL_DB_Error(fmt("sqlite3_step failed - {}", ::sqlite3_errmsg(::sqlite3_db_handle(m_stmt))), rc);
}

Sqlite3_Database::Sqlite3_Statement::~Sqlite3_Statement() {
   ::sqlite3_finalize(m_stmt);
}

}  // namespace Botan
