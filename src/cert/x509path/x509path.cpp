/*
* X.509 Certificate Path Validation
* (C) 2010-2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/x509path.h>
#include <botan/parsing.h>
#include <botan/pubkey.h>
#include <botan/oids.h>
#include <botan/time.h>
#include <algorithm>
#include <memory>

namespace Botan {

Path_Validation_Result x509_path_validate(
   const X509_Certificate& cert,
   const std::vector<Certificate_Store*>& certstores)
   {
   const X509_DN issuer_dn = cert.issuer_dn();
   const MemoryVector<byte> auth_key_id = cert.authority_key_id();

   Path_Validation_Result result;

   std::vector<X509_Certificate> cert_path;

   cert_path.push_back(cert);

   for(size_t i = 0; i != certstores.size(); ++i)
      {
      std::vector<X509_Certificate> got =
         certstores[i]->find_cert_by_subject_and_key_id(issuer_dn, auth_key_id);

      // What to do if it returns more than one match?
      if(got.size() == 1)
         {
         cert_path.push_back(got[0]);
         break;
         }
      }

   return result;
   }

}
