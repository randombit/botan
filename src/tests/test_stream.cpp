/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_STREAM_CIPHER)
#include <botan/stream_cipher.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_STREAM_CIPHER)

class Stream_Cipher_Tests : public Text_Based_Test
   {
   public:
      Stream_Cipher_Tests(): Text_Based_Test("stream",
                                             {"Key", "In", "Out"}, {"Nonce", "Seek"}) {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> key      = get_req_bin(vars, "Key");
         const std::vector<uint8_t> input    = get_req_bin(vars, "In");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Out");
         const std::vector<uint8_t> nonce    = get_opt_bin(vars, "Nonce");
         const size_t seek                   = get_opt_sz(vars, "Seek", 0);

         Test::Result result(algo);

         const std::vector<std::string> providers = Botan::StreamCipher::providers(algo);

         if(providers.empty())
            {
            result.note_missing("block cipher " + algo);
            return result;
            }

         for(auto&& provider: providers)
            {
            std::unique_ptr<Botan::StreamCipher> cipher(Botan::StreamCipher::create(algo, provider));

            if(!cipher)
               {
               result.note_missing(algo + " from " + provider);
               continue;
               }

            result.test_eq(provider, cipher->name(), algo);
            cipher->set_key(key);

            if(nonce.size())
               cipher->set_iv(nonce.data(), nonce.size());

            if (seek != 0)
               cipher->seek(seek);

            std::vector<uint8_t> buf = input;
            cipher->encrypt(buf);

            result.test_eq(provider, "encrypt", buf, expected);
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("stream", Stream_Cipher_Tests);

#endif

}
