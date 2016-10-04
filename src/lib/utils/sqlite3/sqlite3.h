/*
* SQLite3 wrapper
* (C) 2012,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTILS_SQLITE3_H__
#define BOTAN_UTILS_SQLITE3_H__

#include <botan/database.h>

class sqlite3;
class sqlite3_stmt;

namespace Botan {

class BOTAN_DLL Sqlite3_Database  : public SQL_Database
   {
   public:
      Sqlite3_Database(const std::string& file);

      ~Sqlite3_Database();

      size_t row_count(const std::string& table_name) override;

      void create_table(const std::string& table_schema) override;

      std::shared_ptr<Statement> new_statement(const std::string& sql) const override;
   private:
      class Sqlite3_Statement : public Statement
         {
         public:
            void bind(int column, const std::string& val) override;
            void bind(int column, size_t val) override;
            void bind(int column, std::chrono::system_clock::time_point time) override;
            void bind(int column, const std::vector<byte>& val) override;
            void bind(int column, const byte* data, size_t len) override;

            std::pair<const byte*, size_t> get_blob(int column) override;
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
