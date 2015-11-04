
#include "tests.h"

#define CATCH_CONFIG_RUNNER
#define CATCH_CONFIG_CONSOLE_WIDTH 60
#define CATCH_CONFIG_COLOUR_NONE
#include "catchy/catch.hpp"

namespace Botan_Tests {

class Catch_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         int catch_result = Catch::Session().run();

         Test::Result result("Catch");
         if(catch_result != 0)
            result.test_failure("Catch tests failed: " + std::to_string(catch_result));
         return std::vector<Test::Result>{result};
         }
   };

BOTAN_REGISTER_TEST("catch", Catch_Tests);

}
