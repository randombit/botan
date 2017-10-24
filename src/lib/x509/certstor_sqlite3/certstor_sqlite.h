/*
* Certificate Store in SQL
* (C) 2016 Kai Michaelis, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CERT_STORE_SQLITE_H_
#define BOTAN_CERT_STORE_SQLITE_H_

#include <botan/certstor_sql.h>

namespace Botan {

/**
* Certificate and private key store backed by an sqlite (https://sqlite.org) database.
*/
class BOTAN_PUBLIC_API(2,0) Certificate_Store_In_SQLite final : public Certificate_Store_In_SQL
   {
   public:
      /**
      * Create/open a certificate store.
      * @param db_path path to the database file
      * @param passwd password to encrypt private keys in the database
      * @param rng used for encrypting keys
      * @param table_prefix optional prefix for db table names
      */
      Certificate_Store_In_SQLite(const std::string& db_path,
                                  const std::string& passwd,
                                  RandomNumberGenerator& rng,
                                  const std::string& table_prefix = "");
   };
}
#endif
