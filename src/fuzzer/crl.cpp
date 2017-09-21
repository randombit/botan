/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"
#include <botan/x509_crl.h>
#include <botan/data_src.h>

void fuzz(const uint8_t in[], size_t len)
   {
   try
      {
      Botan::DataSource_Memory input(in, len);
      Botan::X509_CRL crl(input);
      }
   catch(Botan::Exception& e) {}
   }
