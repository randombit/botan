/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "driver.h"

#include <botan/x509_crl.h>

void fuzz(const uint8_t in[], size_t len) {
  if (len > 4096) {
    return;
  }

  try {
    DataSource_Memory input(in, len);
    X509_CRL crl(input);
  }
  catch (Botan::Exception& e) { }
}
