/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/database.h>

#include <botan/internal/charset.h>
#include <string>

namespace Botan {

bool SQL_Database::is_valid_table_name(std::string_view table) const {
   if(table.empty()) {
      return false;
   }

   constexpr auto valid_table_name_char = CharacterValidityTable::alpha_numeric_plus("_");
   for(const char c : table) {
      if(!valid_table_name_char(c)) {
         return false;
      }
   }
   return true;
}

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
