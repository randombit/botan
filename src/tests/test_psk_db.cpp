/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PSK_DB)

   #include <botan/psk_db.h>

   #if defined(BOTAN_HAS_SQLITE3)
      #include <botan/sqlite3.h>
   #endif

namespace Botan_Tests {

namespace {

class Test_Map_PSK_Db : public Botan::Encrypted_PSK_Database {
   public:
      explicit Test_Map_PSK_Db(const Botan::secure_vector<uint8_t>& master_key) :
            Botan::Encrypted_PSK_Database(master_key) {}

      void test_entry(Test::Result& result, const std::string& index, const std::string& value) {
         auto i = m_vals.find(index);

         if(i == m_vals.end()) {
            result.test_failure("Expected to find encrypted name " + index);
         } else {
            result.test_eq("Encrypted value", i->second, value);
         }
      }

      void kv_set(std::string_view index, std::string_view value) override {
         m_vals.insert_or_assign(std::string(index), std::string(value));
      }

      std::string kv_get(std::string_view index) const override {
         auto i = m_vals.find(index);
         if(i == m_vals.end()) {
            return "";
         }
         return i->second;
      }

      void kv_del(std::string_view index) override {
         auto i = m_vals.find(index);
         if(i != m_vals.end()) {
            m_vals.erase(i);
         }
      }

      std::set<std::string> kv_get_all() const override {
         std::set<std::string> names;

         for(const auto& kv : m_vals) {
            names.insert(kv.first);
         }

         return names;
      }

   private:
      std::map<std::string, std::string, std::less<>> m_vals;
};

}  // namespace

class PSK_DB_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_psk_db());

   #if defined(BOTAN_HAS_SQLITE3)
         results.push_back(test_psk_sql_db());
   #endif

         return results;
      }

   private:
      static Test::Result test_psk_db() {
         Test::Result result("PSK_DB");

         const Botan::secure_vector<uint8_t> zeros(32);
         Test_Map_PSK_Db db(zeros);

         db.set_str("name", "value");
         db.test_entry(result, "CUCJjJgWSa079ubutJQwlw==", "clYJSAf9CThuL96CP+rAfA==");
         result.test_eq("DB read", db.get_str("name"), "value");

         db.set_str("name", "value1");
         db.test_entry(result, "CUCJjJgWSa079ubutJQwlw==", "7R8am3x/gLawOzMp5WwIJg==");
         result.test_eq("DB read", db.get_str("name"), "value1");

         db.set_str("name", "value");
         db.test_entry(result, "CUCJjJgWSa079ubutJQwlw==", "clYJSAf9CThuL96CP+rAfA==");
         result.test_eq("DB read", db.get_str("name"), "value");

         db.set_str("name2", "value");
         db.test_entry(result, "7CvsM7HDCZsV6VsFwWylNg==", "BqVQo4rdwOmf+ItCzEmjAg==");
         result.test_eq("DB read", db.get_str("name2"), "value");

         db.set_vec("name2", zeros);
         db.test_entry(result, "7CvsM7HDCZsV6VsFwWylNg==", "x+I1bUF/fJYPOTvKwOihEPWGR1XGzVuyRdsw4n5gpBRzNR7LjH7vjw==");
         result.test_eq("DB read", db.get("name2"), zeros);

         // Test longer names
         db.set_str("leroy jeeeeeeeenkins", "chicken");
         db.test_entry(result, "KyYo272vlSjClM2F0OZBMlRYjr33ZXv2jN1oY8OfCEs=", "tCl1qShSTsXi9tA5Kpo9vg==");
         result.test_eq("DB read", db.get_str("leroy jeeeeeeeenkins"), "chicken");

         std::set<std::string> all_names = db.list_names();

         result.test_eq("Expected number of names", all_names.size(), 3);
         result.test_eq("Have expected name", all_names.count("name"), 1);
         result.test_eq("Have expected name", all_names.count("name2"), 1);
         result.test_eq("Have expected name", all_names.count("leroy jeeeeeeeenkins"), 1);

         db.remove("name2");

         all_names = db.list_names();

         result.test_eq("Expected number of names", all_names.size(), 2);
         result.test_eq("Have expected name", all_names.count("name"), 1);
         result.test_eq("Have expected name", all_names.count("leroy jeeeeeeeenkins"), 1);

         result.test_throws(
            "exception if get called on non-existent PSK", "Named PSK not located", [&]() { db.get("name2"); });

         // test that redundant remove calls accepted
         db.remove("name2");

         return result;
      }

   #if defined(BOTAN_HAS_SQLITE3)

      void test_entry(Test::Result& result,
                      Botan::SQL_Database& db,
                      const std::string& table,
                      const std::string& expected_name,
                      const std::string& expected_value) {
         auto stmt = db.new_statement("select psk_value from " + table + " where psk_name='" + expected_name + "'");

         bool got_it = stmt->step();
         result.confirm("Had expected name", got_it);

         if(got_it) {
            result.test_eq("Had expected value", stmt->get_str(0), expected_value);
         }
      }

      Test::Result test_psk_sql_db() {
         Test::Result result("PSK_DB SQL");

         const Botan::secure_vector<uint8_t> zeros(32);
         const Botan::secure_vector<uint8_t> not_zeros = this->rng().random_vec(32);

         const std::string table_name = "bobby";
         std::shared_ptr<Botan::SQL_Database> sqldb = std::make_shared<Botan::Sqlite3_Database>(":memory:");

         Botan::Encrypted_PSK_Database_SQL db(zeros, sqldb, table_name);
         db.set_str("name", "value");

         test_entry(result, *sqldb, table_name, "CUCJjJgWSa079ubutJQwlw==", "clYJSAf9CThuL96CP+rAfA==");
         result.test_eq("DB read", db.get_str("name"), "value");

         db.set_str("name", "value1");
         test_entry(result, *sqldb, table_name, "CUCJjJgWSa079ubutJQwlw==", "7R8am3x/gLawOzMp5WwIJg==");
         result.test_eq("DB read", db.get_str("name"), "value1");

         db.set_str("name", "value");
         test_entry(result, *sqldb, table_name, "CUCJjJgWSa079ubutJQwlw==", "clYJSAf9CThuL96CP+rAfA==");
         result.test_eq("DB read", db.get_str("name"), "value");

         db.set_str("name2", "value");
         test_entry(result, *sqldb, table_name, "7CvsM7HDCZsV6VsFwWylNg==", "BqVQo4rdwOmf+ItCzEmjAg==");
         result.test_eq("DB read", db.get_str("name2"), "value");

         db.set_vec("name2", zeros);
         test_entry(result,
                    *sqldb,
                    table_name,
                    "7CvsM7HDCZsV6VsFwWylNg==",
                    "x+I1bUF/fJYPOTvKwOihEPWGR1XGzVuyRdsw4n5gpBRzNR7LjH7vjw==");
         result.test_eq("DB read", db.get("name2"), zeros);

         // Test longer names
         db.set_str("leroy jeeeeeeeenkins", "chicken");
         test_entry(
            result, *sqldb, table_name, "KyYo272vlSjClM2F0OZBMlRYjr33ZXv2jN1oY8OfCEs=", "tCl1qShSTsXi9tA5Kpo9vg==");
         result.test_eq("DB read", db.get_str("leroy jeeeeeeeenkins"), "chicken");

         /*
         * Test that we can have another database in the same table with distinct key
         * without any problems.
         */
         Botan::Encrypted_PSK_Database_SQL db2(not_zeros, sqldb, table_name);
         db2.set_str("name", "price&value");
         result.test_eq("DB read", db2.get_str("name"), "price&value");
         result.test_eq("DB2 size", db2.list_names().size(), 1);

         std::set<std::string> all_names = db.list_names();

         result.test_eq("Expected number of names", all_names.size(), 3);
         result.test_eq("Have expected name", all_names.count("name"), 1);
         result.test_eq("Have expected name", all_names.count("name2"), 1);
         result.test_eq("Have expected name", all_names.count("leroy jeeeeeeeenkins"), 1);

         db.remove("name2");

         all_names = db.list_names();

         result.test_eq("Expected number of names", all_names.size(), 2);
         result.test_eq("Have expected name", all_names.count("name"), 1);
         result.test_eq("Have expected name", all_names.count("leroy jeeeeeeeenkins"), 1);

         result.test_throws(
            "exception if get called on non-existent PSK", "Named PSK not located", [&]() { db.get("name2"); });

         // test that redundant remove calls accepted
         db.remove("name2");

         return result;
      }
   #endif
};

BOTAN_REGISTER_TEST("misc", "psk_db", PSK_DB_Tests);

}  // namespace Botan_Tests

#endif
