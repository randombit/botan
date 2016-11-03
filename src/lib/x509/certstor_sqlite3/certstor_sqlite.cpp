/*
* Certificate Store in SQL
* (C) 2016 Kai Michaelis, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/certstor_sqlite.h>
#include <botan/sqlite3.h>

namespace Botan {

Certificate_Store_In_SQLite::Certificate_Store_In_SQLite(const std::string& db_path,
                                                         const std::string& passwd,
                                                         RandomNumberGenerator& rng,
                                                         const std::string& table_prefix) :
   Certificate_Store_In_SQL(std::make_shared<Sqlite3_Database>(db_path), passwd, rng, table_prefix)
   {}
}
