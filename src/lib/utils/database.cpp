/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/database.h>

#include <string>

namespace Botan {

std::shared_ptr<SQL_Database::Statement> SQL_Database::select(std::string_view columns,
                                                              std::string_view table,
                                                              std::string_view where,
                                                              std::optional<size_t> limit) const {
   std::string sql = "SELECT ";
   sql += columns;
   sql += " FROM ";
   sql += table;
   if(!where.empty()) {
      sql += " WHERE ";
      sql += where;
   }
   if(limit.has_value()) {
      sql += " LIMIT ";
      sql += std::to_string(*limit);
   }
   return new_statement(sql);
}

}  // namespace Botan
