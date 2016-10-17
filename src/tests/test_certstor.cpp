/*
* (C) 2016 Kai Michaelis, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_CERTSTOR_SQLITE3)
   #include <botan/certstor_sqlite.h>
   #include <botan/sqlite3.h>
   #include <botan/internal/filesystem.h>
   #include <botan/pkcs8.h>
   #include <botan/auto_rng.h>
   #include <sstream>
   extern "C" {
   #include <unistd.h> // unlink()
   }
#endif


namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_CERTSTOR_SQLITE3)

Test::Result test_certstor_insert_find_remove_test(
      const std::vector<std::pair<Botan::X509_Certificate,std::shared_ptr<Botan::Private_Key>>>& certs,
      Botan::Certificate_Store_In_SQL& store)
   {
   Test::Result result("Certificate Store - Insert, Find, Remove");

   for(auto cert_key: certs)
      {
      auto cert = cert_key.first;
      auto key = cert_key.second;
      auto wo_keyid = store.find_cert(cert.subject_dn(),{});
      auto w_keyid = store.find_cert(cert.subject_dn(),cert.subject_key_id());

      if(!wo_keyid || !w_keyid)
         {
         result.test_failure("Can't retrieve certificate");
         return result;
         }

      auto priv = store.find_key(cert);
      if(!priv && (certs[1] != cert_key && certs[0] != cert_key))
         {
         result.test_failure("Can't retrieve private key for " + cert.fingerprint("SHA1"));
         return result;
         }

      result.test_eq("Got wrong certificate",cert.fingerprint(),w_keyid->fingerprint());

      if(priv)
         {
         result.test_eq("Got wrong private key",key->pkcs8_private_key(),priv->pkcs8_private_key());

         auto rev_certs = store.find_certs_for_key(*priv);

         if(rev_certs.empty())
            {
            result.test_failure("No certificate");
            }
         else
            {
               bool found = std::any_of(rev_certs.begin(),rev_certs.end(),[&](std::shared_ptr<const Botan::X509_Certificate> c)
                     { return c->fingerprint() == cert.fingerprint(); });

               result.test_eq("Got wrong/no certificate",found,true);
            }
         }

      if(certs[4] != cert_key && certs[5] != cert_key)
         {
         result.test_eq("Got wrong certificate",cert.fingerprint(),wo_keyid->fingerprint());
         }
         
      result.test_eq("Can't remove certificate",store.remove_cert(cert),true);
      result.test_eq("Can't remove certificate",!store.find_cert(cert.subject_dn(),cert.subject_key_id()),true);

      if(priv)
         {
         store.remove_key(*key);
         }

      result.test_eq("Can't remove key",!store.find_key(cert),true);
      }

   return result;
   }

Test::Result test_certstor_crl_test(
      const std::vector<std::pair<Botan::X509_Certificate,std::shared_ptr<Botan::Private_Key>>>& certs,
      Botan::Certificate_Store_In_SQL& store)
   {
   Test::Result result("Certificate Store - CRL");

   store.revoke_cert(certs[0].first,Botan::CA_COMPROMISE);
   store.revoke_cert(certs[3].first,Botan::CA_COMPROMISE);
   store.revoke_cert(certs[3].first,Botan::CA_COMPROMISE);

   {
      auto crls = store.generate_crls();

      result.test_eq("Can't revoke certificate",crls.size(),2);
      result.test_eq("Can't revoke certificate",crls[0].is_revoked(certs[0].first) ^ crls[1].is_revoked(certs[0].first),true);
      result.test_eq("Can't revoke certificate",crls[0].is_revoked(certs[3].first) ^ crls[1].is_revoked(certs[3].first),true);
   }

   store.affirm_cert(certs[3].first);

   {
      auto crls = store.generate_crls();

      result.test_eq("Can't revoke certificate, wrong crl size",crls.size(),1);
      result.test_eq("Can't revoke certificate, cert 0 not revoked",crls[0].is_revoked(certs[0].first),true);
   }

   auto cert0_crl = store.find_crl_for(certs[0].first);

   result.test_eq("Can't revoke certificate, crl for cert 0",!cert0_crl,false);
   result.test_eq("Can't revoke certificate, crl for cert 0 size check",cert0_crl->get_revoked().size(),1);
   result.test_eq("Can't revoke certificate, no crl for cert 0",cert0_crl->is_revoked(certs[0].first),true);

   auto cert3_crl = store.find_crl_for(certs[3].first);

   result.test_eq("Can't revoke certificate, crl for cert 3",!cert3_crl,true);

   return result;
   }

Test::Result test_certstor_all_subjects_test(
      const std::vector<std::pair<Botan::X509_Certificate,std::shared_ptr<Botan::Private_Key>>>& certs,
      Botan::Certificate_Store_In_SQL& store)
   {
   Test::Result result("Certificate Store - All subjects");

   auto subjects = store.all_subjects();
      
   result.test_eq("Check subject list length",subjects.size(),6);

   for(auto sub: subjects)
      {
      std::stringstream ss;

      ss << sub;
      result.test_eq("Check subject " + ss.str(),
            certs[0].first.subject_dn() == sub ||
            certs[1].first.subject_dn() == sub ||
            certs[2].first.subject_dn() == sub ||
            certs[3].first.subject_dn() == sub ||
            certs[4].first.subject_dn() == sub ||
            certs[5].first.subject_dn() == sub,true);
   
      }
   return result;
   }

class Certstor_Tests : public Test
   {
   public:
         std::vector<Test::Result> run() override
         {
         const std::string test_dir = Test::data_dir() + "/certstor";
         const std::vector<std::pair<std::string,std::string>> test_data({
            std::make_pair("cert1.crt","key01.pem"),
            std::make_pair("cert2.crt","key01.pem"),
            std::make_pair("cert3.crt","key03.pem"),
            std::make_pair("cert4.crt","key04.pem"),
            std::make_pair("cert5a.crt","key05.pem"),
            std::make_pair("cert5b.crt","key06.pem")
         });

         std::vector<Test::Result> results;
         std::vector<std::pair<std::string,std::function<Test::Result(
               const std::vector<std::pair<Botan::X509_Certificate,std::shared_ptr<Botan::Private_Key>>>&,
               Botan::Certificate_Store_In_SQL&)>>>
            fns({
            std::make_pair("Certificate Store - Insert, Find, Remove",test_certstor_insert_find_remove_test),
            std::make_pair("Certificate Store - CRL",test_certstor_crl_test),
            std::make_pair("Certificate Store - All subjects",test_certstor_all_subjects_test)
            });

         try
            {
            // Do nothing, just test filesystem access
            Botan::get_files_recursive(test_dir);
            }
         catch(Botan::No_Filesystem_Access&)
            {
            Test::Result result("Certificate Store");
            result.test_note("Skipping due to missing filesystem access");
            return {result};
            }

         const std::vector<std::string> all_files = Botan::get_files_recursive(test_dir);

         if(all_files.empty())
            {
            Test::Result result("Certificate Store");
            result.test_failure("No test files found in " + test_dir);
            return {result};
            }

         for(auto fn: fns)
            {
            Test::Result result(fn.first);

            try
               {
               unlink((fn.first + ".db").c_str());

               auto& rng = Test::rng();
               std::string passwd(reinterpret_cast<const char*>(rng.random_vec(8).data()),8);
               Botan::Certificate_Store_In_SQLite store(fn.first + ".db", passwd, rng);
               std::vector<std::pair<Botan::X509_Certificate,std::shared_ptr<Botan::Private_Key>>> retrieve;

               for(auto&& cert_key_pair : test_data)
                  {
                  Botan::X509_Certificate cert(test_dir + "/" + cert_key_pair.first);
                  std::shared_ptr<Botan::Private_Key> key(Botan::PKCS8::load_key(test_dir + "/" + cert_key_pair.second,rng));

                  if(!key)
                     {
                     result.test_failure("Failed to load key from disk");
                     results.push_back(fn.second(retrieve,store));
                     continue;
                     }


                  store.insert_cert(cert);
                  store.insert_key(cert,*key);
                  retrieve.push_back(std::make_pair(cert,key));
                  } 

               results.push_back(fn.second(retrieve,store));
               }
            catch(std::exception& e)
               {
               results.push_back(Test::Result::Failure("Certstor test '" + fn.first + "'", e.what()));
               }
            }

         return results;
         }
   };

BOTAN_REGISTER_TEST("certstor", Certstor_Tests);

#endif

}

}
