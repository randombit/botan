/*
* SQLite3 wrapper
* (C) 2012,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTILS_SQLITE3_H_
#define BOTAN_UTILS_SQLITE3_H_

#include <botan/database.h>

#include <optional>

struct sqlite3;
struct sqlite3_stmt;

namespace Botan {

class BOTAN_PUBLIC_API(2, 0) Sqlite3_Database final : public SQL_Database {
   public:
      /**
       * Create a new SQLite database handle from a file.
       *
       * @param file               path to the database file be opened and/or created
       * @param sqlite_open_flags  flags that will be passed to sqlite3_open_v2()
       *                           (default: SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX)
       */
      Sqlite3_Database(std::string_view file, std::optional<int> sqlite_open_flags = std::nullopt);

      ~Sqlite3_Database() override;

      size_t row_count(std::string_view table_name) override;

      void create_table(std::string_view table_schema) override;

      size_t rows_changed_by_last_statement() override;

      std::shared_ptr<Statement> new_statement(std::string_view sql) const override;

      bool is_threadsafe() const override;

   private:
      class Sqlite3_Statement final : public Statement {
         public:
            void bind(int column, std::string_view val) override;
            void bind(int column, size_t val) override;
            void bind(int column, std::chrono::system_clock::time_point time) override;
            void bind(int column, const std::vector<uint8_t>& val) override;
            void bind(int column, const uint8_t* data, size_t len) override;

            std::pair<const uint8_t*, size_t> get_blob(int column) override;
            std::string get_str(int column) override;
            size_t get_size_t(int column) override;

            size_t spin() override;
            bool step() override;

            Sqlite3_Statement(sqlite3* db, std::string_view base_sql);
            ~Sqlite3_Statement() override;

         private:
            sqlite3_stmt* m_stmt;
      };

      sqlite3* m_db;
};

}  // namespace Botan

#endif
