/*
* SQLite3 wrapper
* (C) 2012,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTILS_SQLITE3_H_
#define BOTAN_UTILS_SQLITE3_H_

#include <botan/database.h>

class sqlite3;
class sqlite3_stmt;

namespace Botan {

class BOTAN_PUBLIC_API(2,0) Sqlite3_Database final : public SQL_Database
   {
   public:
      Sqlite3_Database(const std::string& file);

      ~Sqlite3_Database();

      size_t row_count(const std::string& table_name) override;

      void create_table(const std::string& table_schema) override;

      std::shared_ptr<Statement> new_statement(const std::string& sql) const override;
   private:
      class Sqlite3_Statement final : public Statement
         {
         public:
            void bind(int column, const std::string& val) override;
            void bind(int column, size_t val) override;
            void bind(int column, std::chrono::system_clock::time_point time) override;
            void bind(int column, const std::vector<uint8_t>& val) override;
            void bind(int column, const uint8_t* data, size_t len) override;

            std::pair<const uint8_t*, size_t> get_blob(int column) override;
            std::string get_str(int column) override;
            size_t get_size_t(int column) override;

            size_t spin() override;
            bool step() override;

            Sqlite3_Statement(sqlite3* db, const std::string& base_sql);
            ~Sqlite3_Statement();
         private:
            sqlite3_stmt* m_stmt;
         };

      sqlite3* m_db;
   };

}

#endif
