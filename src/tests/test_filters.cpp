/*
* (C) 2016 Daniel Neus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_FILTERS)
    #include <botan/secqueue.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_FILTERS)

class Filter_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;
         Test::Result secqueue_result("SecureQueue");

         try
            {
            using Botan::SecureQueue;
            SecureQueue queueA;
            std::vector<uint8_t> testData = {0x24, 0xB2, 0xBF, 0xC2, 0xE6, 0xD4, 0x7E, 0x04, 0x67, 0xB3};
            queueA.write(testData.data(), testData.size());

            secqueue_result.test_eq("size of SecureQueue is correct", queueA.size(), testData.size());
            secqueue_result.test_eq("0 bytes read so far from SecureQueue", queueA.get_bytes_read(), 0);

            uint8_t byte;
            size_t bytesRead = queueA.read_byte(byte);
            secqueue_result.test_eq("1 byte read", bytesRead, 1);

            Botan::secure_vector<uint8_t> produced(byte);
            Botan::secure_vector<uint8_t> expected(testData.at( 0 ));
            secqueue_result.test_eq("byte read is correct", produced, expected);

            secqueue_result.test_eq("1 bytes read so far from SecureQueue", queueA.get_bytes_read(), 1);

            SecureQueue queueB;
            queueA = queueB;
            secqueue_result.test_eq("bytes_read is set correctly", queueA.get_bytes_read(), 0);
            }
         catch (std::exception& e)
            {
            secqueue_result.test_failure("SecureQueue", e.what());
            }

         results.push_back(secqueue_result);
         return results;
         }	
   };

   BOTAN_REGISTER_TEST("filter", Filter_Tests);

#endif

}
