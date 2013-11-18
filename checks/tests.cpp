#include "validate.h"
#include <iostream>

void run_tests(std::istream& src,
               const std::string& name_key,
               const std::string& output_key,
               bool clear_between_cb,
               std::function<std::string (std::map<std::string, std::string>)> cb)
   {
   std::map<std::string, std::string> vars;
   size_t test_cnt = 0;
   size_t test_fail = 0;
   bool verbose = true;

   while(src.good())
      {
      std::string line;
      std::getline(src, line);

      if(line == "")
         continue;

      // FIXME: strip # comments

      // FIXME: Do this right

      const std::string key = line.substr(0, line.find_first_of(' '));
      const std::string val = line.substr(line.find_last_of(' ') + 1, std::string::npos);

      vars[key] = val;

      if(key == output_key)
         {
         ++test_cnt;
         const std::string got = cb(vars);

         if(got != val)
            {
            ++test_fail;
            std::cout << name_key << " #" << test_cnt
                      << " got " << got << " expected " << val << std::endl;
            }

         if(clear_between_cb)
            vars.clear();
         }
      }

   if(verbose)
      std::cout << test_cnt << " " << name_key << " tests completed "
                << test_fail << " failed\n";
   }

