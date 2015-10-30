/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_MODES)

#include <botan/hex.h>
#include <botan/cipher_mode.h>
#include <iostream>
#include <fstream>
#include <memory>

using namespace Botan;

namespace {

size_t mode_test(const std::string& algo,
                 const std::vector<byte>& pt,
                 const std::vector<byte>& ct,
                 const std::vector<byte>& key,
                 const std::vector<byte>& nonce)
   {
   size_t fails = 0;

   std::unique_ptr<Cipher_Mode> enc(get_cipher_mode(algo, ENCRYPTION));
   std::unique_ptr<Cipher_Mode> dec(get_cipher_mode(algo, DECRYPTION));

   if(!enc || !dec)
      return warn_about_missing(algo);

   enc->set_key(key);
   enc->start(nonce);

   dec->set_key(key);
   dec->start(nonce);

   secure_vector<byte> buf;

   buf.assign(pt.begin(), pt.end());
   enc->finish(buf);
   fails += test_buffers_equal(algo, "encrypt", buf, ct);

   buf.assign(ct.begin(), ct.end());
   dec->finish(buf);
   fails += test_buffers_equal(algo, "decrypt", buf, pt);

   return fails;
   }

}

size_t test_modes()
   {
   auto test = [](const std::string& input)
      {
      std::ifstream vec(input);

      return run_tests_bb(vec, "Mode", "Out", true,
             [](std::map<std::string, std::string> m)
             {
             return mode_test(m["Mode"],
                              hex_decode(m["In"]),
                              hex_decode(m["Out"]),
                              hex_decode(m["Key"]),
                              hex_decode(m["Nonce"]));
             });
      };

   return run_tests_in_dir(TEST_DATA_DIR "/modes", test);
   }

#else

SKIP_TEST(modes);

#endif // BOTAN_HAS_MODES
