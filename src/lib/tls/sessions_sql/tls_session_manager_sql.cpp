/*
* SQL TLS Session Manager
* (C) 2012,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_session_manager_sql.h>

#include <botan/database.h>
#include <botan/hex.h>
#include <botan/pwdhash.h>
#include <botan/rng.h>
#include <botan/internal/loadstor.h>
#include <chrono>

namespace Botan::TLS {

Session_Manager_SQL::Session_Manager_SQL(std::shared_ptr<SQL_Database> db,
                                         std::string_view passphrase,
                                         const std::shared_ptr<RandomNumberGenerator>& rng,
                                         size_t max_sessions) :
      Session_Manager(rng), m_db(std::move(db)), m_max_sessions(max_sessions) {
   create_or_migrate_and_open(passphrase);
}

void Session_Manager_SQL::create_or_migrate_and_open(std::string_view passphrase) {
   switch(detect_schema_revision()) {
      case CORRUPTED:
      case PRE_BOTAN_3_0:
      case EMPTY:
         // Legacy sessions before Botan 3.0 are simply dropped, no actual
         // migration is implemented. Same for apparently corrupt databases.
         m_db->exec("DROP TABLE IF EXISTS tls_sessions");
         m_db->exec("DROP TABLE IF EXISTS tls_sessions_metadata");
         create_with_latest_schema(passphrase, BOTAN_3_0);
         break;
      case BOTAN_3_0:
         initialize_existing_database(passphrase);
         break;
      default:
         throw Internal_Error("TLS session db has unknown database schema");
   }
}

Session_Manager_SQL::Schema_Revision Session_Manager_SQL::detect_schema_revision() {
   try {
      const auto meta_data_rows = m_db->row_count("tls_sessions_metadata");
      if(meta_data_rows != 1) {
         return CORRUPTED;
      }
   } catch(const SQL_Database::SQL_DB_Error&) {
      return EMPTY;  // `tls_sessions_metadata` probably didn't exist at all
   }

   try {
      auto stmt = m_db->new_statement("SELECT database_revision FROM tls_sessions_metadata");
      if(!stmt->step()) {
         throw Internal_Error("Failed to read revision of TLS session database");
      }
      return Schema_Revision(stmt->get_size_t(0));
   } catch(const SQL_Database::SQL_DB_Error&) {
      return PRE_BOTAN_3_0;  // `database_revision` did not exist yet -> preparing the statement failed
   }
}

void Session_Manager_SQL::create_with_latest_schema(std::string_view passphrase, Schema_Revision rev) {
   m_db->create_table(
      "CREATE TABLE tls_sessions "
      "("
      "session_id TEXT PRIMARY KEY, "
      "session_ticket BLOB, "
      "session_start INTEGER, "
      "hostname TEXT, "
      "hostport INTEGER, "
      "session BLOB NOT NULL"
      ")");

   m_db->create_table(
      "CREATE TABLE tls_sessions_metadata "
      "("
      "passphrase_salt BLOB, "
      "passphrase_iterations INTEGER, "
      "passphrase_check INTEGER, "
      "password_hash_family TEXT, "
      "database_revision INTEGER"
      ")");

   // speeds up lookups on session_tickets when deleting
   m_db->create_table("CREATE INDEX tls_tickets ON tls_sessions (session_ticket)");

   auto salt = m_rng->random_vec<std::vector<uint8_t>>(16);

   secure_vector<uint8_t> derived_key(32 + 2);

   const auto pbkdf_name = "PBKDF2(SHA-512)";
   auto pbkdf_fam = PasswordHashFamily::create_or_throw(pbkdf_name);

   auto desired_runtime = std::chrono::milliseconds(100);
   auto pbkdf = pbkdf_fam->tune(derived_key.size(), desired_runtime);

   pbkdf->derive_key(
      derived_key.data(), derived_key.size(), passphrase.data(), passphrase.size(), salt.data(), salt.size());

   const size_t iterations = pbkdf->iterations();
   const size_t check_val = make_uint16(derived_key[0], derived_key[1]);
   m_session_key = SymmetricKey(std::span(derived_key).subspan(2));

   auto stmt = m_db->new_statement("INSERT INTO tls_sessions_metadata VALUES (?1, ?2, ?3, ?4, ?5)");

   stmt->bind(1, salt);
   stmt->bind(2, iterations);
   stmt->bind(3, check_val);
   stmt->bind(4, pbkdf_name);
   stmt->bind(5, rev);

   stmt->spin();
}

void Session_Manager_SQL::initialize_existing_database(std::string_view passphrase) {
   auto stmt = m_db->new_statement("SELECT * FROM tls_sessions_metadata");
   if(!stmt->step()) {
      throw Internal_Error("Failed to initialize TLS session database");
   }

   std::pair<const uint8_t*, size_t> salt = stmt->get_blob(0);
   const size_t iterations = stmt->get_size_t(1);
   const size_t check_val_db = stmt->get_size_t(2);
   const std::string pbkdf_name = stmt->get_str(3);

   secure_vector<uint8_t> derived_key(32 + 2);

   auto pbkdf_fam = PasswordHashFamily::create_or_throw(pbkdf_name);
   auto pbkdf = pbkdf_fam->from_params(iterations);

   pbkdf->derive_key(
      derived_key.data(), derived_key.size(), passphrase.data(), passphrase.size(), salt.first, salt.second);

   const size_t check_val_created = make_uint16(derived_key[0], derived_key[1]);

   if(check_val_created != check_val_db) {
      throw Invalid_Argument("Session database password not valid");
   }

   m_session_key = SymmetricKey(std::span(derived_key).subspan(2));
}

void Session_Manager_SQL::store(const Session& session, const Session_Handle& handle) {
   std::optional<lock_guard_type<recursive_mutex_type>> lk;
   if(!database_is_threadsafe()) {
      lk.emplace(mutex());
   }

   if(session.server_info().hostname().empty()) {
      return;
   }

   auto stmt = m_db->new_statement(
      "INSERT OR REPLACE INTO tls_sessions"
      " VALUES (?1, ?2, ?3, ?4, ?5, ?6)");

   // Generate a random session ID if the peer did not provide one. Note that
   // this ID will not be returned on ::find(), as the ticket is preferred.
   const auto id = handle.id().value_or(m_rng->random_vec<Session_ID>(32));
   const auto ticket = handle.ticket().value_or(Session_Ticket());

   stmt->bind(1, hex_encode(id.get()));
   stmt->bind(2, ticket.get());
   stmt->bind(3, session.start_time());
   stmt->bind(4, session.server_info().hostname());
   stmt->bind(5, session.server_info().port());
   stmt->bind(6, session.encrypt(m_session_key, *m_rng));

   stmt->spin();

   prune_session_cache();
}

std::optional<Session> Session_Manager_SQL::retrieve_one(const Session_Handle& handle) {
   std::optional<lock_guard_type<recursive_mutex_type>> lk;
   if(!database_is_threadsafe()) {
      lk.emplace(mutex());
   }

   if(auto session_id = handle.id()) {
      auto stmt = m_db->new_statement("SELECT session FROM tls_sessions WHERE session_id = ?1");

      stmt->bind(1, hex_encode(session_id->get()));

      while(stmt->step()) {
         std::pair<const uint8_t*, size_t> blob = stmt->get_blob(0);

         try {
            return Session::decrypt(blob.first, blob.second, m_session_key);
         } catch(...) {}
      }
   }

   return std::nullopt;
}

std::vector<Session_with_Handle> Session_Manager_SQL::find_some(const Server_Information& info,
                                                                const size_t max_sessions_hint) {
   std::optional<lock_guard_type<recursive_mutex_type>> lk;
   if(!database_is_threadsafe()) {
      lk.emplace(mutex());
   }

   auto stmt = m_db->new_statement(
      "SELECT session_id, session_ticket, session FROM tls_sessions"
      " WHERE hostname = ?1 AND hostport = ?2"
      " ORDER BY session_start DESC"
      " LIMIT ?3");

   stmt->bind(1, info.hostname());
   stmt->bind(2, info.port());
   stmt->bind(3, max_sessions_hint);

   std::vector<Session_with_Handle> found_sessions;
   while(stmt->step()) {
      auto handle = [&]() -> Session_Handle {
         auto ticket_blob = stmt->get_blob(1);
         if(ticket_blob.second > 0) {
            return Session_Ticket(std::span(ticket_blob.first, ticket_blob.second));
         } else {
            return Session_ID(Botan::hex_decode(stmt->get_str(0)));
         }
      }();

      std::pair<const uint8_t*, size_t> blob = stmt->get_blob(2);

      try {
         found_sessions.emplace_back(
            Session_with_Handle{Session::decrypt(blob.first, blob.second, m_session_key), std::move(handle)});
      } catch(...) {}
   }

   return found_sessions;
}

size_t Session_Manager_SQL::remove(const Session_Handle& handle) {
   // The number of deleted rows is taken globally from the database connection,
   // therefore we need to serialize this implementation.
   lock_guard_type<recursive_mutex_type> lk(mutex());

   if(const auto id = handle.id()) {
      auto stmt = m_db->new_statement("DELETE FROM tls_sessions WHERE session_id = ?1");
      stmt->bind(1, hex_encode(id->get()));
      stmt->spin();
   } else if(const auto ticket = handle.ticket()) {
      auto stmt = m_db->new_statement("DELETE FROM tls_sessions WHERE session_ticket = ?1");
      stmt->bind(1, ticket->get());
      stmt->spin();
   } else {
      // should not happen, as session handles are exclusively either an ID or a ticket
      throw Invalid_Argument("provided a session handle that is neither ID nor ticket");
   }

   return m_db->rows_changed_by_last_statement();
}

size_t Session_Manager_SQL::remove_all() {
   // The number of deleted rows is taken globally from the database connection,
   // therefore we need to serialize this implementation.
   lock_guard_type<recursive_mutex_type> lk(mutex());

   m_db->exec("DELETE FROM tls_sessions");
   return m_db->rows_changed_by_last_statement();
}

void Session_Manager_SQL::prune_session_cache() {
   // internal API: assuming that the lock is held already if needed

   if(m_max_sessions == 0) {
      return;
   }

   auto remove_oldest = m_db->new_statement(
      "DELETE FROM tls_sessions WHERE session_id NOT IN "
      "(SELECT session_id FROM tls_sessions ORDER BY session_start DESC LIMIT ?1)");
   remove_oldest->bind(1, m_max_sessions);
   remove_oldest->spin();
}

}  // namespace Botan::TLS
