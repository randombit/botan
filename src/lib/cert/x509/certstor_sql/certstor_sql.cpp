/*
* Certificate Store in SQL
* (C) 2016 Kai Michaelis, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/certstor_sql.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/internal/filesystem.h>
#include <botan/pkcs8.h>
#include <botan/data_src.h>
#include <botan/auto_rng.h>
#include <botan/hash.h>
#include <botan/hex.h>

namespace Botan {

Certificate_Store_In_SQL::Certificate_Store_In_SQL(std::shared_ptr<SQL_Database> db,
                                                   const std::string& passwd,
                                                   const std::string& table_prefix)
: m_database(db), m_prefix(table_prefix), m_password(passwd)
   {
   m_database->create_table("CREATE TABLE IF NOT EXISTS certificates ( \
                                 fingerprint       BLOB PRIMARY KEY,   \
                                 subject_dn        BLOB,               \
                                 key_id            BLOB,               \
                                 priv_fingerprint  BLOB,               \
                                 certificate       BLOB UNIQUE NOT NULL\
                             )");
   m_database->create_table("CREATE TABLE IF NOT EXISTS keys (   \
                                 fingerprint BLOB PRIMARY KEY,   \
                                 key         BLOB UNIQUE NOT NULL\
                             )");
   m_database->create_table("CREATE TABLE IF NOT EXISTS revoked (\
                                 fingerprint BLOB PRIMARY KEY,   \
                                 reason      BLOB NOT NULL,      \
                                 time        BLOB NOT NULL       \
                            )");
   }

// Certificate handling
std::shared_ptr<const X509_Certificate>
Certificate_Store_In_SQL::find_cert(const X509_DN& subject_dn, const std::vector<byte>& key_id) const
   {
   DER_Encoder enc;
   std::shared_ptr<SQL_Database::Statement> stmt;

   subject_dn.encode_into(enc);

   if(key_id.empty())
      {
      stmt = m_database->new_statement("SELECT certificate FROM certificates WHERE subject_dn == ?1");
      stmt->bind(1,enc.get_contents_unlocked());
      }
   else
      {
      stmt = m_database->new_statement("SELECT certificate FROM certificates WHERE\
                                        subject_dn == ?1 AND (key_id == NULL OR key_id == ?2)");
      stmt->bind(1,enc.get_contents_unlocked());
      stmt->bind(2,key_id);
      }

   std::shared_ptr<const X509_Certificate> cert;
   while(stmt->step())
      {
      auto blob = stmt->get_blob(0);
      cert = std::make_shared<X509_Certificate>(
            std::vector<byte>(blob.first,blob.first + blob.second));

      }

   return cert;
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
   auto stmt = m_database->new_statement("SELECT subject_dn FROM certificates");

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
   if(find_cert(cert.subject_dn(),cert.subject_key_id()))
      return false;

   DER_Encoder enc;
   auto stmt = m_database->new_statement("INSERT OR REPLACE INTO certificates (\
                                         fingerprint,                          \
                                         subject_dn,                           \
                                         key_id,                               \
                                         priv_fingerprint,                     \
                                         certificate                           \
                                     ) VALUES ( ?1, ?2, ?3, ?4, ?5 )");

   stmt->bind(1,cert.fingerprint("SHA-256"));
   cert.subject_dn().encode_into(enc);
   stmt->bind(2,enc.get_contents_unlocked());
   stmt->bind(3,cert.subject_key_id());
   stmt->bind(4,std::vector<byte>());
   enc = DER_Encoder();
   cert.encode_into(enc);
   stmt->bind(5,enc.get_contents_unlocked());
   stmt->spin();

   return true;
   }


bool Certificate_Store_In_SQL::remove_cert(const X509_Certificate& cert)
   {
   if(!find_cert(cert.subject_dn(),cert.subject_key_id()))
      return false;

   auto stmt = m_database->new_statement("DELETE FROM certificates WHERE fingerprint == ?1");

   stmt->bind(1,cert.fingerprint("SHA-256"));
   stmt->spin();

   return true;
   }

// Private key handling
std::shared_ptr<const Private_Key> Certificate_Store_In_SQL::find_key(const X509_Certificate& cert) const
   {
   auto stmt = m_database->new_statement("SELECT key FROM keys JOIN certificates ON keys.fingerprint == certificates.priv_fingerprint WHERE certificates.fingerprint == ?1");
   stmt->bind(1,cert.fingerprint("SHA-256"));

   std::shared_ptr<const Private_Key> key;
   while(stmt->step())
      {
      auto blob = stmt->get_blob(0);
      AutoSeeded_RNG rng;
      DataSource_Memory src(blob.first,blob.second);
      key.reset(PKCS8::load_key(src,rng,m_password));
      }

   return key;
   }

std::vector<std::shared_ptr<const X509_Certificate>>
Certificate_Store_In_SQL::find_certs_for_key(const Private_Key& key) const
   {
   AutoSeeded_RNG rng;
   auto fpr = fingerprint_key(key);
   auto stmt = m_database->new_statement("SELECT certificate FROM certificates WHERE priv_fingerprint == ?1");

   stmt->bind(1,fpr);

   std::shared_ptr<const X509_Certificate> cert;
   while(stmt->step())
      {
      auto blob = stmt->get_blob(0);
      cert = std::make_shared<X509_Certificate>(
            std::vector<byte>(blob.first,blob.first + blob.second));
      }

   return {cert};
   }

bool Certificate_Store_In_SQL::insert_key(const X509_Certificate& cert, const Private_Key& key) {
   insert_cert(cert);

   if(find_key(cert))
      return false;

   AutoSeeded_RNG rng;
   auto pkcs8 = PKCS8::BER_encode(key,rng,m_password);
   auto fpr = fingerprint_key(key);

   //m_database->new_statement("BEGIN TRANSACTION")->spin();

   auto stmt1 = m_database->new_statement(
         "INSERT OR REPLACE INTO keys ( fingerprint, key ) VALUES ( ?1, ?2 )");

   stmt1->bind(1,fpr);
   stmt1->bind(2,pkcs8.data(),pkcs8.size());
   stmt1->spin();

   auto stmt2 = m_database->new_statement(
         "UPDATE certificates SET priv_fingerprint = ?1 WHERE fingerprint == ?2");

   stmt2->bind(1,fpr);
   stmt2->bind(2,cert.fingerprint("SHA-256"));
   stmt2->spin();

   //m_database->new_statement("END TRANSACTION")->spin();
   
   return true;
   }

std::string Certificate_Store_In_SQL::fingerprint_key(const Botan::Private_Key& key) const
   {
   secure_vector<byte> buf = key.pkcs8_private_key();
   std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-256"));
   hash->update(buf);
   const auto hex_print = hex_encode(hash->final());

   std::string formatted_print;

   for(size_t i = 0; i != hex_print.size(); i += 2)
      {
      formatted_print.push_back(hex_print[i]);
      formatted_print.push_back(hex_print[i+1]);

      if(i != hex_print.size() - 2)
         formatted_print.push_back(':');
      }

   return formatted_print;
   }

void Certificate_Store_In_SQL::remove_key(const Private_Key& key)
   {
   AutoSeeded_RNG rng;
   auto fpr = fingerprint_key(key);
   auto stmt = m_database->new_statement("DELETE FROM keys WHERE fingerprint == ?1");

   stmt->bind(1,fpr);
   stmt->spin();
   }

// Revocation
void Certificate_Store_In_SQL::revoke_cert(const X509_Certificate& cert, CRL_Code code, const X509_Time& time)
   {
   insert_cert(cert);

   auto stmt1 = m_database->new_statement(
         "INSERT OR REPLACE INTO revoked ( fingerprint, reason, time ) VALUES ( ?1, ?2, ?3 )");

   stmt1->bind(1,cert.fingerprint("SHA-256"));
   stmt1->bind(2,code);

   if(time.time_is_set())
      {
      DER_Encoder der;
      time.encode_into(der);
      stmt1->bind(3,der.get_contents_unlocked());
      }
   else
      {
      stmt1->bind(3,-1);
      }

   stmt1->spin();
   }

void Certificate_Store_In_SQL::affirm_cert(const X509_Certificate& cert)
   {
   auto stmt = m_database->new_statement("DELETE FROM revoked WHERE fingerprint == ?1");

   stmt->bind(1,cert.fingerprint("SHA-256"));
   stmt->spin();
   }

std::vector<X509_CRL> Certificate_Store_In_SQL::generate_crls() const
   {
   auto stmt = m_database->new_statement(
         "SELECT certificate,reason,time FROM revoked JOIN certificates ON certificates.fingerprint == revoked.fingerprint");

   std::map<X509_DN,std::vector<CRL_Entry>> crls;
   while(stmt->step())
      {
      auto blob = stmt->get_blob(0);
      auto cert = X509_Certificate(
            std::vector<byte>(blob.first,blob.first + blob.second));
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
