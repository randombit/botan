/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/hex.h>

#if defined(BOTAN_HAS_RFC3394_KEYWRAP)
  #include <botan/rfc3394.h>
#endif

#include <iostream>

using namespace Botan;

namespace {

#if defined(BOTAN_HAS_RFC3394_KEYWRAP)
size_t keywrap_test(const char* key_str,
                    const char* expected_hex,
                    const char* kek_str)
   {
   size_t fail = 0;

   try
      {
      SymmetricKey key(key_str);
      SymmetricKey expected(expected_hex);
      SymmetricKey kek(kek_str);

      secure_vector<byte> enc = rfc3394_keywrap(key.bits_of(), kek);

      fail += test_buffers_equal("NIST key wrap", "encryption", enc, expected.bits_of());

      secure_vector<byte> dec = rfc3394_keyunwrap(expected.bits_of(), kek);

      fail += test_buffers_equal("NIST key wrap", "decryption", dec, key.bits_of());
      }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      fail++;
      }

   return fail;
   }
#endif

}

size_t test_keywrap()
   {
   size_t fails = 0;

#if defined(BOTAN_HAS_RFC3394_KEYWRAP)
   fails += keywrap_test("00112233445566778899AABBCCDDEEFF",
                         "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
                         "000102030405060708090A0B0C0D0E0F");

   fails += keywrap_test("00112233445566778899AABBCCDDEEFF",
                         "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
                         "000102030405060708090A0B0C0D0E0F1011121314151617");

   fails += keywrap_test("00112233445566778899AABBCCDDEEFF",
                         "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
                         "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

   fails += keywrap_test("00112233445566778899AABBCCDDEEFF0001020304050607",
                         "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
                         "000102030405060708090A0B0C0D0E0F1011121314151617");

   fails += keywrap_test("00112233445566778899AABBCCDDEEFF0001020304050607",
                         "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
                         "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

   fails += keywrap_test("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
                         "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
                         "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

   test_report("NIST keywrap", 6, fails);
#endif

   return fails;
   }
