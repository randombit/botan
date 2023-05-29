/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/psk_db.h>

#include <botan/database.h>

namespace Botan {

Encrypted_PSK_Database_SQL::Encrypted_PSK_Database_SQL(const secure_vector<uint8_t>& master_key,
                                                       std::shared_ptr<SQL_Database> db,
                                                       std::string_view table_name) :
      Encrypted_PSK_Database(master_key), m_db(std::move(db)), m_table_name(table_name) {
   m_db->create_table("create table if not exists " + m_table_name + "(psk_name TEXT PRIMARY KEY, psk_value TEXT)");
}

Encrypted_PSK_Database_SQL::~Encrypted_PSK_Database_SQL() = default;

void Encrypted_PSK_Database_SQL::kv_del(std::string_view name) {
   auto stmt = m_db->new_statement("delete from " + m_table_name + " where psk_name=?1");
   stmt->bind(1, name);
   stmt->spin();
}

void Encrypted_PSK_Database_SQL::kv_set(std::string_view name, std::string_view value) {
   auto stmt = m_db->new_statement("insert or replace into " + m_table_name + " values(?1, ?2)");

   stmt->bind(1, name);
   stmt->bind(2, value);

   stmt->spin();
}

std::string Encrypted_PSK_Database_SQL::kv_get(std::string_view name) const {
   auto stmt = m_db->new_statement("select psk_value from " + m_table_name + " where psk_name = ?1");

   stmt->bind(1, name);

   while(stmt->step()) {
      return stmt->get_str(0);
   }
   return "";
}

std::set<std::string> Encrypted_PSK_Database_SQL::kv_get_all() const {
   std::set<std::string> names;

   auto stmt = m_db->new_statement("select psk_name from " + m_table_name);

   while(stmt->step()) {
      names.insert(stmt->get_str(0));
   }

   return names;
}

}  // namespace Botan
