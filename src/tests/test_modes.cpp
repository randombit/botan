/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_MODES)
  #include <botan/cipher_mode.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_MODES)

class Cipher_Mode_Tests : public Text_Based_Test
   {
   public:
      Cipher_Mode_Tests() :
         Text_Based_Test("modes", {"Key", "Nonce", "In", "Out"})
         {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> key      = get_req_bin(vars, "Key");
         const std::vector<uint8_t> nonce    = get_opt_bin(vars, "Nonce");
         const std::vector<uint8_t> input    = get_req_bin(vars, "In");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Out");

         Test::Result result(algo);

         std::unique_ptr<Botan::Cipher_Mode> enc(Botan::get_cipher_mode(algo, Botan::ENCRYPTION));
         std::unique_ptr<Botan::Cipher_Mode> dec(Botan::get_cipher_mode(algo, Botan::DECRYPTION));

         if(!enc || !dec)
            {
            result.note_missing(algo);
            return result;
            }

         result.test_is_nonempty("provider", enc->provider());
         result.test_eq("name", enc->name(), algo);

         result.test_eq("mode not authenticated", enc->authenticated(), false);

         enc->set_key(key);
         enc->start(nonce);

         Botan::secure_vector<uint8_t> buf(input.begin(), input.end());
         // TODO: should first update if possible
         enc->finish(buf);

         result.test_eq("encrypt", buf, expected);

         buf.assign(expected.begin(), expected.end());

         dec->set_key(key);
         dec->start(nonce);
         dec->finish(buf);
         result.test_eq("decrypt", buf, input);

         enc->clear();
         dec->clear();

         return result;
         }
   };

BOTAN_REGISTER_TEST("modes", Cipher_Mode_Tests);

#endif

}
