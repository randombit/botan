/*
* SQLite3 wrapper
* (C) 2012,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTILS_SQLITE3_H_
#define BOTAN_UTILS_SQLITE3_H_

#include <botan/database.h>

#include <memory>
#include <optional>

struct sqlite3;
struct sqlite3_stmt;

namespace Botan {

/**
* An SQL_Database implementation backed by SQLite3
*/
class BOTAN_PUBLIC_API(2, 0) Sqlite3_Database final : public SQL_Database {
   public:
      /**
       * Create a new SQLite database handle from a file.
       *
       * @param file               path to the database file be opened and/or created
       * @param sqlite_open_flags  flags that will be passed to sqlite3_open_v2()
       *                           (default: SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX)
       */
      BOTAN_FUTURE_EXPLICIT Sqlite3_Database(std::string_view file,
                                             std::optional<int> sqlite_open_flags = std::nullopt);

      ~Sqlite3_Database() override;

      // Database handles are not copyable or moveable
      Sqlite3_Database(const Sqlite3_Database& other) = delete;
      Sqlite3_Database(Sqlite3_Database&& other) = delete;
      Sqlite3_Database& operator=(const Sqlite3_Database& other) = delete;
      Sqlite3_Database& operator=(Sqlite3_Database&& other) = delete;

      /**
      * Count the rows of a table
      * @param table_name the table to count
      * @return the number of rows in the table
      */
      size_t row_count(std::string_view table_name) override;

      /**
      * Create a table
      * @param schema the name and columns of the table to create
      */
      void create_table(const Table_Schema& schema) override;

      /**
      * Count the rows modified by the most recently executed statement
      * @return the number of rows inserted, updated or deleted
      */
      size_t rows_changed_by_last_statement() override;

      /**
      * Create a new statement for execution
      * @param sql the SQL text of the statement
      * @return the prepared statement
      */
      std::shared_ptr<Statement> new_statement(std::string_view sql) const override;

      /**
      * Prepare an insert-or-replace statement
      * @param table the table to upsert into
      * @param columns the columns to write, in placeholder order
      * @return the prepared statement
      */
      std::shared_ptr<Statement> upsert(std::string_view table,
                                        std::initializer_list<std::string_view> columns) const override;

      /**
      * Query whether this database may be used from multiple threads
      * @return true if SQLite3 was compiled with threading support
      */
      bool is_threadsafe() const override;

   private:
      class Sqlite3_Statement final : public Statement {
         public:
            void bind(int column, std::string_view val) override;
            void bind(int column, size_t val) override;
            void bind(int column, std::chrono::system_clock::time_point time) override;
            void bind(int column, const std::vector<uint8_t>& val) override;
            void bind(int column, const uint8_t* data, size_t len) override;
            void bind_null(int column) override;

            std::span<const uint8_t> get_blob(int column) override;
            std::optional<std::string> get_str(int column) override;
            size_t get_size_t(int column) override;

            size_t spin() override;
            bool step() override;

            Sqlite3_Statement(std::shared_ptr<sqlite3> db, std::string_view base_sql);
            ~Sqlite3_Statement() override;

            Sqlite3_Statement(const Sqlite3_Statement& other) = delete;
            Sqlite3_Statement(Sqlite3_Statement&& other) = delete;
            Sqlite3_Statement& operator=(const Sqlite3_Statement& other) = delete;
            Sqlite3_Statement& operator=(Sqlite3_Statement&& other) = delete;

         private:
            // m_db is declared before m_stmt so the prepared statement is
            // finalized before the connection's refcount is released.
            std::shared_ptr<sqlite3> m_db;
            sqlite3_stmt* m_stmt;
      };

      std::shared_ptr<sqlite3> m_db;
};

}  // namespace Botan

#endif
