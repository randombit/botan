/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"
#include <botan/x509cert.h>
#include <botan/data_src.h>

void fuzz(const uint8_t in[], size_t len)
   {
   if(len > max_fuzzer_input_size)
      return;

   try
      {
      Botan::DataSource_Memory input(in, len);
      Botan::X509_Certificate cert(input);
      }
   catch(Botan::Exception& e) { }
   }
