/*
* (C) 2022 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/data_src.h>
#include <botan/x509cert.h>
#include <botan/x509path.h>

void fuzz(const uint8_t in[], size_t len) {
   Botan::DataSource_Memory input(in, len);

   try {
      Botan::X509_Certificate subject(input);
      Botan::X509_Certificate issuer(input);

      std::vector<Botan::Certificate_Store*> roots;
      std::unique_ptr<Botan::Certificate_Store> root_store(new Botan::Certificate_Store_In_Memory(issuer));
      roots.push_back(root_store.get());

      Botan::Path_Validation_Restrictions restrictions;

      x509_path_validate({subject}, restrictions, roots);
   } catch(Botan::Exception& e) {}
}
