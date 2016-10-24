/*
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_CIPHER_MODE_PADDING)
  #include <botan/mode_pad.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_CIPHER_MODE_PADDING)

class Cipher_Mode_Padding_Tests : public Text_Based_Test
   {
   public:
      Cipher_Mode_Padding_Tests() :
         Text_Based_Test("pad.vec", {"In", "Out", "Blocksize"})
         {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> input    = get_req_bin(vars, "In");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Out");
         const size_t block_size = get_req_sz(vars, "Blocksize");

         Test::Result result(algo);

         std::unique_ptr<Botan::BlockCipherModePaddingMethod> pad(Botan::get_bc_pad(algo));

         if(!pad)
            {
            result.test_failure("Invalid padding method: " + algo);
            return result;
            }

         Botan::secure_vector<uint8_t> buf(input.begin(), input.end());
         pad->add_padding(buf, input.size() % block_size, block_size);
         result.test_eq("pad", buf, expected);

         buf.assign(expected.begin(), expected.end());

         const size_t last_block = ( buf.size() < block_size ) ? 0 : buf.size() - block_size;
         const size_t pad_bytes = block_size - pad->unpad(&buf[last_block], block_size);
         buf.resize(buf.size() - pad_bytes); // remove padding
         result.test_eq("unpad", buf, input);

         return result;
         }
   };

BOTAN_REGISTER_TEST("bc_pad", Cipher_Mode_Padding_Tests);

#endif

}
