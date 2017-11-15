/*
* (C) 2016,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"
#include <botan/asn1_print.h>
#include <fstream>

void fuzz(const uint8_t in[], size_t len)
   {
   try
      {
      /*
      * Here we use an uninitialized ofstream so the fuzzer doesn't spend time
      * on actual output formatting, no memory is allocated, etc.
      */
      std::ofstream out;
      Botan::ASN1_Pretty_Printer printer;
      printer.print_to_stream(out, in, len);
      }
   catch(Botan::Exception& e) { }
   }
