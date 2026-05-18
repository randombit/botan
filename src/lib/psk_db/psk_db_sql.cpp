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
   using DB = SQL_Database;
   m_db->create_table(DB::Table_Schema(m_table_name,
                                       {
                                          DB::Column("psk_name", DB::Column_Type::String).primary_key(),
                                          DB::Column("psk_value", DB::Column_Type::String),
                                       })
                         .if_not_exists());
}

Encrypted_PSK_Database_SQL::~Encrypted_PSK_Database_SQL() = default;

void Encrypted_PSK_Database_SQL::kv_del(std::string_view name) {
   auto stmt = m_db->new_statement("delete from " + m_table_name + " where psk_name=?1");
   stmt->bind(1, name);
   stmt->spin();
}

void Encrypted_PSK_Database_SQL::kv_set(std::string_view name, std::string_view value) {
   auto stmt = m_db->upsert(m_table_name, {"psk_name", "psk_value"});

   stmt->bind(1, name);
   stmt->bind(2, value);

   stmt->spin();
}

std::string Encrypted_PSK_Database_SQL::kv_get(std::string_view name) const {
   auto stmt = m_db->select("psk_value", m_table_name, "psk_name = ?1");

   stmt->bind(1, name);

   while(stmt->step()) {
      return stmt->get_str(0).value_or("");
   }
   return "";
}

std::set<std::string> Encrypted_PSK_Database_SQL::kv_get_all() const {
   std::set<std::string> names;

   auto stmt = m_db->select("psk_name", m_table_name);

   while(stmt->step()) {
      names.insert(stmt->get_str(0).value());
   }

   return names;
}

}  // namespace Botan
