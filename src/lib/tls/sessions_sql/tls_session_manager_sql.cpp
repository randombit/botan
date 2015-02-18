/*
* SQL TLS Session Manager
* (C) 2012,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_session_manager_sql.h>
#include <botan/database.h>
#include <botan/pbkdf.h>
#include <botan/lookup.h>
#include <botan/hex.h>
#include <botan/loadstor.h>
#include <chrono>

namespace Botan {

namespace TLS {

namespace {

SymmetricKey derive_key(const std::string& passphrase,
                        const byte salt[],
                        size_t salt_len,
                        size_t iterations,
                        size_t& check_val)
   {
   std::unique_ptr<PBKDF> pbkdf(get_pbkdf("PBKDF2(SHA-512)"));

   secure_vector<byte> x = pbkdf->derive_key(32 + 2,
                                             passphrase,
                                             salt, salt_len,
                                             iterations).bits_of();

   check_val = make_u16bit(x[0], x[1]);
   return SymmetricKey(&x[2], x.size() - 2);
   }

}

Session_Manager_SQL::Session_Manager_SQL(std::shared_ptr<SQL_Database> db,
                                         const std::string& passphrase,
                                         RandomNumberGenerator& rng,
                                         size_t max_sessions,
                                         std::chrono::seconds session_lifetime) :
   m_db(db),
   m_rng(rng),
   m_max_sessions(max_sessions),
   m_session_lifetime(session_lifetime)
   {
   m_db->create_table(
      "create table if not exists tls_sessions "
      "("
      "session_id TEXT PRIMARY KEY, "
      "session_start INTEGER, "
      "hostname TEXT, "
      "hostport INTEGER, "
      "session BLOB"
      ")");

   m_db->create_table(
      "create table if not exists tls_sessions_metadata "
      "("
      "passphrase_salt BLOB, "
      "passphrase_iterations INTEGER, "
      "passphrase_check INTEGER "
      ")");

   const size_t salts = m_db->row_count("tls_sessions_metadata");

   if(salts == 1)
      {
      // existing db
      auto stmt = m_db->new_statement("select * from tls_sessions_metadata");

      if(stmt->step())
         {
         std::pair<const byte*, size_t> salt = stmt->get_blob(0);
         const size_t iterations = stmt->get_size_t(1);
         const size_t check_val_db = stmt->get_size_t(2);

         size_t check_val_created;
         m_session_key = derive_key(passphrase,
                                    salt.first,
                                    salt.second,
                                    iterations,
                                    check_val_created);

         if(check_val_created != check_val_db)
            throw std::runtime_error("Session database password not valid");
         }
      }
   else
      {
      // maybe just zap the salts + sessions tables in this case?
      if(salts != 0)
         throw std::runtime_error("Seemingly corrupted database, multiple salts found");

      // new database case

      std::vector<byte> salt = unlock(rng.random_vec(16));
      const size_t iterations = 256 * 1024;
      size_t check_val = 0;

      m_session_key = derive_key(passphrase, &salt[0], salt.size(),
                                 iterations, check_val);

      auto stmt = m_db->new_statement("insert into tls_sessions_metadata values(?1, ?2, ?3)");

      stmt->bind(1, salt);
      stmt->bind(2, iterations);
      stmt->bind(3, check_val);

      stmt->spin();
      }
   }

bool Session_Manager_SQL::load_from_session_id(const std::vector<byte>& session_id,
                                               Session& session)
   {
   auto stmt = m_db->new_statement("select session from tls_sessions where session_id = ?1");

   stmt->bind(1, hex_encode(session_id));

   while(stmt->step())
      {
      std::pair<const byte*, size_t> blob = stmt->get_blob(0);

      try
         {
         session = Session::decrypt(blob.first, blob.second, m_session_key);
         return true;
         }
      catch(...)
         {
         }
      }

   return false;
   }

bool Session_Manager_SQL::load_from_server_info(const Server_Information& server,
                                                Session& session)
   {
   auto stmt = m_db->new_statement("select session from tls_sessions"
                                   " where hostname = ?1 and hostport = ?2"
                                   " order by session_start desc");

   stmt->bind(1, server.hostname());
   stmt->bind(2, server.port());

   while(stmt->step())
      {
      std::pair<const byte*, size_t> blob = stmt->get_blob(0);

      try
         {
         session = Session::decrypt(blob.first, blob.second, m_session_key);
         return true;
         }
      catch(...)
         {
         }
      }

   return false;
   }

void Session_Manager_SQL::remove_entry(const std::vector<byte>& session_id)
   {
   auto stmt = m_db->new_statement("delete from tls_sessions where session_id = ?1");

   stmt->bind(1, hex_encode(session_id));

   stmt->spin();
   }

void Session_Manager_SQL::save(const Session& session)
   {
   auto stmt = m_db->new_statement("insert or replace into tls_sessions"
                                   " values(?1, ?2, ?3, ?4, ?5)");

   stmt->bind(1, hex_encode(session.session_id()));
   stmt->bind(2, session.start_time());
   stmt->bind(3, session.server_info().hostname());
   stmt->bind(4, session.server_info().port());
   stmt->bind(5, session.encrypt(m_session_key, m_rng));

   stmt->spin();

   prune_session_cache();
   }

void Session_Manager_SQL::prune_session_cache()
   {
   // First expire old sessions
   auto remove_expired = m_db->new_statement("delete from tls_sessions where session_start <= ?1");
   remove_expired->bind(1, std::chrono::system_clock::now() - m_session_lifetime);
   remove_expired->spin();

   const size_t sessions = m_db->row_count("tls_sessions");

   // Then if needed expire some more sessions at random
   if(sessions > m_max_sessions)
      {
      auto remove_some = m_db->new_statement("delete from tls_sessions where session_id in "
                                             "(select session_id from tls_sessions limit ?1)");

      remove_some->bind(1, sessions - m_max_sessions);
      remove_some->spin();
      }
   }

}

}
