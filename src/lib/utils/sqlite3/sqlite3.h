/*
* SQLite wrapper
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_UTILS_SQLITE_WRAPPER_H__
#define BOTAN_UTILS_SQLITE_WRAPPER_H__

#include <botan/types.h>
#include <string>
#include <chrono>
#include <vector>

class sqlite3;
class sqlite3_stmt;

namespace Botan {

class sqlite3_database
   {
   public:
      sqlite3_database(const std::string& file);

      ~sqlite3_database();

      size_t row_count(const std::string& table_name);

      void create_table(const std::string& table_schema);
   private:
      friend class sqlite3_statement;

      sqlite3* m_db;
   };

class sqlite3_statement
   {
   public:
      sqlite3_statement(sqlite3_database* db,
                        const std::string& base_sql);

      void bind(int column, const std::string& val);

      void bind(int column, int val);

      void bind(int column, std::chrono::system_clock::time_point time);

      void bind(int column, const std::vector<byte>& val);

      std::pair<const byte*, size_t> get_blob(int column);

      size_t get_size_t(int column);

      void spin();

      bool step();

      ~sqlite3_statement();
   private:
      sqlite3_stmt* m_stmt;
   };

}

#endif
