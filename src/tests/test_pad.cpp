/*
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_CIPHER_MODE_PADDING)
   #include <botan/internal/mode_pad.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_CIPHER_MODE_PADDING)

class Cipher_Mode_Padding_Tests final : public Text_Based_Test {
   public:
      Cipher_Mode_Padding_Tests() : Text_Based_Test("pad.vec", "In,Blocksize", "Out") {}

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         const std::vector<uint8_t> input = vars.get_req_bin("In");
         const std::vector<uint8_t> expected = vars.get_opt_bin("Out");
         const size_t block_size = vars.get_req_sz("Blocksize");

         std::string algo = header;

         auto underscore = algo.find('_');
         if(underscore != std::string::npos) {
            if(algo.substr(underscore + 1, std::string::npos) != "Invalid") {
               throw Test_Error("Unexpected padding header " + header);
            }
            algo = algo.substr(0, underscore);
         }

         Test::Result result(algo);

         auto pad = Botan::BlockCipherModePaddingMethod::create(algo);

         if(!pad) {
            result.test_failure("Invalid padding method: " + algo);
            return result;
         }

         if(expected.empty()) {
            // This is an unpad an invalid input and ensure we reject
            if(pad->unpad(input.data(), block_size) != block_size) {
               result.test_failure("Did not reject invalid padding", Botan::hex_encode(input));
            } else {
               result.test_success("Rejected invalid padding");
            }
         } else {
            // This is a pad plaintext and unpad valid padding round trip test
            Botan::secure_vector<uint8_t> buf(input.begin(), input.end());
            pad->add_padding(buf, input.size() % block_size, block_size);
            result.test_eq("pad", buf, expected);

            buf.assign(expected.begin(), expected.end());

            const size_t last_block = (buf.size() < block_size) ? 0 : buf.size() - block_size;
            const size_t pad_bytes = block_size - pad->unpad(&buf[last_block], block_size);
            buf.resize(buf.size() - pad_bytes);  // remove padding
            result.test_eq("unpad", buf, input);
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("modes", "bc_pad", Cipher_Mode_Padding_Tests);

#endif

}  // namespace Botan_Tests
