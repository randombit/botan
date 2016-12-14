/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "driver.h"

#include <botan/x509cert.h>

void fuzz(const uint8_t in[], size_t len)
   {
   if(len > 8192)
      return;

   try
      {
      DataSource_Memory input(in, len);
      X509_Certificate cert(input);
      }
   catch(Botan::Exception& e) { }
   }
