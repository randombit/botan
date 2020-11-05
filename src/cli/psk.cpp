/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_PSK_DB) && defined(BOTAN_HAS_SQLITE3)

#include <botan/psk_db.h>
#include <botan/sqlite3.h>
#include <botan/hex.h>

namespace Botan_CLI {

class PSK_Tool_Base : public Command
   {
   public:
      PSK_Tool_Base(const std::string& spec) : Command(spec) {}

      std::string group() const override
         {
         return "psk";
         }

      void go() override
         {
         const std::string db_filename = get_arg("db");
         const Botan::secure_vector<uint8_t> db_key = Botan::hex_decode_locked(get_passphrase_arg("Database key", "db_key"));

         std::shared_ptr<Botan::SQL_Database> db = std::make_shared<Botan::Sqlite3_Database>(db_filename);
         Botan::Encrypted_PSK_Database_SQL psk(db_key, db, "psk");

         psk_operation(psk);
         }

   private:
      virtual void psk_operation(Botan::PSK_Database& db) = 0;
   };

class PSK_Tool_Set final : public PSK_Tool_Base
   {
   public:
      PSK_Tool_Set() : PSK_Tool_Base("psk_set db db_key name psk") {}

      std::string description() const override
         {
         return "Save a PSK encrypted in the database";
         }

   private:
      void psk_operation(Botan::PSK_Database& db) override
         {
         const std::string name = get_arg("name");
         const Botan::secure_vector<uint8_t> psk = Botan::hex_decode_locked(get_passphrase_arg("PSK", "psk"));
         db.set_vec(name, psk);
         }
   };

class PSK_Tool_Get final : public PSK_Tool_Base
   {
   public:
      PSK_Tool_Get() : PSK_Tool_Base("psk_get db db_key name") {}

      std::string description() const override
         {
         return "Read a value saved with psk_set";
         }

   private:
      void psk_operation(Botan::PSK_Database& db) override
         {
         const std::string name = get_arg("name");
         const Botan::secure_vector<uint8_t> val = db.get(name);
         output() << Botan::hex_encode(val) << "\n";
         }
   };

class PSK_Tool_List final : public PSK_Tool_Base
   {
   public:
      PSK_Tool_List() : PSK_Tool_Base("psk_list db db_key") {}

      std::string description() const override
         {
         return "List all values saved to the database";
         }

   private:
      void psk_operation(Botan::PSK_Database& db) override
         {
         const std::set<std::string> names = db.list_names();

         for(std::string name : names)
            output() << name << "\n";
         }
   };

BOTAN_REGISTER_COMMAND("psk_set", PSK_Tool_Set);
BOTAN_REGISTER_COMMAND("psk_get", PSK_Tool_Get);
BOTAN_REGISTER_COMMAND("psk_list", PSK_Tool_List);

}

#endif
