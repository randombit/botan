/*
* Certificate Store in SQL
* (C) 2016 Kai Michaelis, Rohde & Schwarz Cybersecurity
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/certstor_sql.h>
#include <botan/pk_keys.h>
#include <botan/ber_dec.h>
#include <botan/pkcs8.h>
#include <botan/data_src.h>
#include <botan/pkix_types.h>

namespace Botan {

Certificate_Store_In_SQL::Certificate_Store_In_SQL(std::shared_ptr<SQL_Database> db,
                                                   const std::string& passwd,
                                                   RandomNumberGenerator& rng,
                                                   const std::string& table_prefix) :
   m_rng(rng),
   m_database(db),
   m_prefix(table_prefix),
   m_password(passwd)
   {
   m_database->create_table("CREATE TABLE IF NOT EXISTS " +
                             m_prefix + "certificates (                \
                                 fingerprint       BLOB PRIMARY KEY,   \
                                 subject_dn        BLOB,               \
                                 key_id            BLOB,               \
                                 priv_fingerprint  BLOB,               \
                                 certificate       BLOB UNIQUE NOT NULL\
                             )");
   m_database->create_table("CREATE TABLE IF NOT EXISTS " + m_prefix + "keys (\
                                 fingerprint BLOB PRIMARY KEY,                \
                                 key         BLOB UNIQUE NOT NULL             \
                             )");
   m_database->create_table("CREATE TABLE IF NOT EXISTS " + m_prefix + "revoked (\
                                 fingerprint BLOB PRIMARY KEY,                   \
                                 reason      BLOB NOT NULL,                      \
                                 time        BLOB NOT NULL                       \
                            )");
   }

// Certificate handling
std::shared_ptr<const X509_Certificate>
Certificate_Store_In_SQL::find_cert(const X509_DN& subject_dn, const std::vector<uint8_t>& key_id) const
   {
   std::shared_ptr<SQL_Database::Statement> stmt;

   const std::vector<uint8_t> dn_encoding = subject_dn.BER_encode();

   if(key_id.empty())
      {
      stmt = m_database->new_statement("SELECT certificate FROM " + m_prefix + "certificates WHERE subject_dn == ?1 LIMIT 1");
      stmt->bind(1, dn_encoding);
      }
   else
      {
      stmt = m_database->new_statement("SELECT certificate FROM " + m_prefix + "certificates WHERE\
                                        subject_dn == ?1 AND (key_id == NULL OR key_id == ?2) LIMIT 1");
      stmt->bind(1, dn_encoding);
      stmt->bind(2,key_id);
      }

   while(stmt->step())
      {
      auto blob = stmt->get_blob(0);
      return std::make_shared<X509_Certificate>(std::vector<uint8_t>(blob.first, blob.first + blob.second));
      }

   return std::shared_ptr<const X509_Certificate>();
   }

std::vector<std::shared_ptr<const X509_Certificate>>
Certificate_Store_In_SQL::find_all_certs(const X509_DN& subject_dn, const std::vector<uint8_t>& key_id) const
   {
   std::vector<std::shared_ptr<const X509_Certificate>> certs;

   std::shared_ptr<SQL_Database::Statement> stmt;

   const std::vector<uint8_t> dn_encoding = subject_dn.BER_encode();

   if(key_id.empty())
      {
      stmt = m_database->new_statement("SELECT certificate FROM " + m_prefix + "certificates WHERE subject_dn == ?1");
      stmt->bind(1, dn_encoding);
      }
   else
      {
      stmt = m_database->new_statement("SELECT certificate FROM " + m_prefix + "certificates WHERE\
                                        subject_dn == ?1 AND (key_id == NULL OR key_id == ?2)");
      stmt->bind(1, dn_encoding);
      stmt->bind(2, key_id);
      }

   std::shared_ptr<const X509_Certificate> cert;
   while(stmt->step())
      {
      auto blob = stmt->get_blob(0);
      certs.push_back(std::make_shared<X509_Certificate>(
            std::vector<uint8_t>(blob.first,blob.first + blob.second)));
      }

   return certs;
   }

std::shared_ptr<const X509_Certificate>
Certificate_Store_In_SQL::find_cert_by_pubkey_sha1(const std::vector<uint8_t>& /*key_hash*/) const
   {
   throw Not_Implemented("Certificate_Store_In_SQL::find_cert_by_pubkey_sha1");
   }

std::shared_ptr<const X509_Certificate>
Certificate_Store_In_SQL::find_cert_by_raw_subject_dn_sha256(const std::vector<uint8_t>& /*subject_hash*/) const
   {
   throw Not_Implemented("Certificate_Store_In_SQL::find_cert_by_raw_subject_dn_sha256");
   }

std::shared_ptr<const X509_CRL>
Certificate_Store_In_SQL::find_crl_for(const X509_Certificate& subject) const
   {
   auto all_crls = generate_crls();

   for(auto crl: all_crls)
      {
      if(!crl.get_revoked().empty() && crl.issuer_dn() == subject.issuer_dn())
         return std::shared_ptr<X509_CRL>(new X509_CRL(crl));
      }

   return std::shared_ptr<X509_CRL>();
   }

std::vector<X509_DN> Certificate_Store_In_SQL::all_subjects() const
   {
   std::vector<X509_DN> ret;
   auto stmt = m_database->new_statement("SELECT subject_dn FROM " + m_prefix + "certificates");

   while(stmt->step())
      {
      auto blob = stmt->get_blob(0);
      BER_Decoder dec(blob.first,blob.second);
      X509_DN dn;

      dn.decode_from(dec);

      ret.push_back(dn);
      }

   return ret;
   }

bool Certificate_Store_In_SQL::insert_cert(const X509_Certificate& cert)
   {
   const std::vector<uint8_t> dn_encoding = cert.subject_dn().BER_encode();
   const std::vector<uint8_t> cert_encoding = cert.BER_encode();

   auto stmt = m_database->new_statement("INSERT OR REPLACE INTO " +
                                     m_prefix + "certificates (\
                                         fingerprint,          \
                                         subject_dn,           \
                                         key_id,               \
                                         priv_fingerprint,     \
                                         certificate           \
                                     ) VALUES ( ?1, ?2, ?3, ?4, ?5 )");

   stmt->bind(1,cert.fingerprint("SHA-256"));
   stmt->bind(2,dn_encoding);
   stmt->bind(3,cert.subject_key_id());
   stmt->bind(4,std::vector<uint8_t>());
   stmt->bind(5,cert_encoding);
   stmt->spin();

   return true;
   }


bool Certificate_Store_In_SQL::remove_cert(const X509_Certificate& cert)
   {
   if(!find_cert(cert.subject_dn(),cert.subject_key_id()))
      return false;

   auto stmt = m_database->new_statement("DELETE FROM " + m_prefix + "certificates WHERE fingerprint == ?1");

   stmt->bind(1,cert.fingerprint("SHA-256"));
   stmt->spin();

   return true;
   }

// Private key handling
std::shared_ptr<const Private_Key> Certificate_Store_In_SQL::find_key(const X509_Certificate& cert) const
   {
   auto stmt = m_database->new_statement("SELECT key FROM " + m_prefix + "keys "
       "JOIN " + m_prefix + "certificates ON " +
       m_prefix + "keys.fingerprint == " + m_prefix + "certificates.priv_fingerprint "
       "WHERE " + m_prefix + "certificates.fingerprint == ?1");
   stmt->bind(1,cert.fingerprint("SHA-256"));

   std::shared_ptr<const Private_Key> key;
   while(stmt->step())
      {
      auto blob = stmt->get_blob(0);
      DataSource_Memory src(blob.first,blob.second);
      key.reset(PKCS8::load_key(src, m_rng, m_password));
      }

   return key;
   }

std::vector<std::shared_ptr<const X509_Certificate>>
Certificate_Store_In_SQL::find_certs_for_key(const Private_Key& key) const
   {
   auto fpr = key.fingerprint_private("SHA-256");
   auto stmt = m_database->new_statement("SELECT certificate FROM " + m_prefix + "certificates WHERE priv_fingerprint == ?1");

   stmt->bind(1,fpr);

   std::vector<std::shared_ptr<const X509_Certificate>> certs;
   while(stmt->step())
      {
      auto blob = stmt->get_blob(0);
      certs.push_back(std::make_shared<X509_Certificate>(
            std::vector<uint8_t>(blob.first,blob.first + blob.second)));
      }

   return certs;
   }

bool Certificate_Store_In_SQL::insert_key(const X509_Certificate& cert, const Private_Key& key) {
   insert_cert(cert);

   if(find_key(cert))
      return false;

   auto pkcs8 = PKCS8::BER_encode(key, m_rng, m_password);
   auto fpr = key.fingerprint_private("SHA-256");

   auto stmt1 = m_database->new_statement(
         "INSERT OR REPLACE INTO " + m_prefix + "keys ( fingerprint, key ) VALUES ( ?1, ?2 )");

   stmt1->bind(1,fpr);
   stmt1->bind(2,pkcs8.data(),pkcs8.size());
   stmt1->spin();

   auto stmt2 = m_database->new_statement(
         "UPDATE " + m_prefix + "certificates SET priv_fingerprint = ?1 WHERE fingerprint == ?2");

   stmt2->bind(1,fpr);
   stmt2->bind(2,cert.fingerprint("SHA-256"));
   stmt2->spin();

   return true;
   }

void Certificate_Store_In_SQL::remove_key(const Private_Key& key)
   {
   auto fpr = key.fingerprint_private("SHA-256");
   auto stmt = m_database->new_statement("DELETE FROM " + m_prefix + "keys WHERE fingerprint == ?1");

   stmt->bind(1,fpr);
   stmt->spin();
   }

// Revocation
void Certificate_Store_In_SQL::revoke_cert(const X509_Certificate& cert, CRL_Code code, const X509_Time& time)
   {
   insert_cert(cert);

   auto stmt1 = m_database->new_statement(
         "INSERT OR REPLACE INTO " + m_prefix + "revoked ( fingerprint, reason, time ) VALUES ( ?1, ?2, ?3 )");

   stmt1->bind(1,cert.fingerprint("SHA-256"));
   stmt1->bind(2,code);

   if(time.time_is_set())
      {
      stmt1->bind(3, time.BER_encode());
      }
   else
      {
      stmt1->bind(3, static_cast<size_t>(-1));
      }

   stmt1->spin();
   }

void Certificate_Store_In_SQL::affirm_cert(const X509_Certificate& cert)
   {
   auto stmt = m_database->new_statement("DELETE FROM " + m_prefix + "revoked WHERE fingerprint == ?1");

   stmt->bind(1,cert.fingerprint("SHA-256"));
   stmt->spin();
   }

std::vector<X509_CRL> Certificate_Store_In_SQL::generate_crls() const
   {
   auto stmt = m_database->new_statement(
         "SELECT certificate,reason,time FROM " + m_prefix + "revoked "
         "JOIN " + m_prefix + "certificates ON " +
         m_prefix + "certificates.fingerprint == " + m_prefix + "revoked.fingerprint");

   std::map<X509_DN,std::vector<CRL_Entry>> crls;
   while(stmt->step())
      {
      auto blob = stmt->get_blob(0);
      auto cert = X509_Certificate(
            std::vector<uint8_t>(blob.first,blob.first + blob.second));
      auto code = static_cast<CRL_Code>(stmt->get_size_t(1));
      auto ent = CRL_Entry(cert,code);

      auto i = crls.find(cert.issuer_dn());
      if(i == crls.end())
         {
         crls.insert(std::make_pair(cert.issuer_dn(),std::vector<CRL_Entry>({ent})));
         }
      else
         {
         i->second.push_back(ent);
         }
      }

   std::vector<X509_CRL> ret;
   X509_Time t(std::chrono::system_clock::now());

   for(auto p: crls)
      {
      ret.push_back(X509_CRL(p.first,t,t,p.second));
      }

   return ret;
   }

}
