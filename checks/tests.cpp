#include "validate.h"
#include <iostream>

void run_tests_bb(std::istream& src,
                  const std::string& name_key,
                  const std::string& output_key,
                  bool clear_between_cb,
                  std::function<bool (std::map<std::string, std::string>)> cb)
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

      if(line[0] == '#')
         continue;

      const std::string key = line.substr(0, line.find_first_of(' '));
      const std::string val = line.substr(line.find_last_of(' ') + 1, std::string::npos);

      vars[key] = val;

      if(key == output_key)
         {
         ++test_cnt;
         bool passed = cb(vars);

         if(!passed)
            ++test_fail;

         if(clear_between_cb)
            vars.clear();
         }
      }

   if(verbose)
      std::cout << test_cnt << " " << name_key << " tests completed "
                << test_fail << " failed\n";
   }

void run_tests(std::istream& src,
               const std::string& name_key,
               const std::string& output_key,
               bool clear_between_cb,
               std::function<std::string (std::map<std::string, std::string>)> cb)
   {
   run_tests_bb(src, name_key, output_key, clear_between_cb,
                [name_key,output_key,cb](std::map<std::string, std::string> vars)
                {
                const std::string got = cb(vars);
                if(got != vars[output_key])
                   {
                   std::cout << name_key << " got " << got
                             << " expected " << vars[output_key] << std::endl;
                   return false;
                   }
                return true;
                });
   }

