/*
* Certificate Store in SQL
* (C) 2016 Kai Michaelis, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CERT_STORE_SQLITE_H__
#define BOTAN_CERT_STORE_SQLITE_H__

#include <botan/certstor_sql.h>

namespace Botan {

class BOTAN_DLL Certificate_Store_In_SQLite : public Certificate_Store_In_SQL
   {
   public:
      Certificate_Store_In_SQLite(const std::string& db_path,
                                           const std::string& passwd,
                                           const std::string& table_prefix = "");
   };
}
#endif
