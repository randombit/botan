#include "tests.h"
#include <iostream>

size_t run_tests(const std::vector<test_fn>& tests)
   {
   size_t fails = 0;
   for(auto& test : tests)
      {
      try
         {
         fails += test();
         }
      catch(std::exception& e)
         {
         std::cout << "Exception escaped callback: " << e.what() << "\n";
         ++fails;
         }
      }
   return fails;
   }

void test_report(const std::string& name, size_t ran, size_t failed)
   {
   std::cout << name << " tests:";

   if(ran > 0)
      std::cout << " " << ran << " total";

   if(failed)
      std::cout << " " << failed << " FAILs\n";
   else
      std::cout << " all ok\n";
   }

size_t run_tests_bb(std::istream& src,
                    const std::string& name_key,
                    const std::string& output_key,
                    bool clear_between_cb,
                    std::function<bool (std::map<std::string, std::string>)> cb)
   {
   if(!src.good())
      {
      std::cout << "Could not open input file for " << name_key << "\n";
      return 1;
      }

   std::map<std::string, std::string> vars;
   size_t test_fails = 0, algo_fail = 0;
   size_t test_count = 0, algo_count = 0;

   std::string fixed_name;

   while(src.good())
      {
      std::string line;
      std::getline(src, line);

      if(line == "")
         continue;

      if(line[0] == '#')
         continue;

      if(line[0] == '[' && line[line.size()-1] == ']')
         {
         if(fixed_name != "")
            test_report(fixed_name, algo_count, algo_fail);

         test_count += algo_count;
         test_fails += algo_fail;
         algo_count = 0;
         algo_fail = 0;
         fixed_name = line.substr(1, line.size() - 2);
         vars[name_key] = fixed_name;
         continue;
         }

      const std::string key = line.substr(0, line.find_first_of(' '));
      const std::string val = line.substr(line.find_last_of(' ') + 1, std::string::npos);

      vars[key] = val;

      if(key == name_key)
         fixed_name.clear();

      if(key == output_key)
         {
         //std::cout << vars[name_key] << " " << test_cnt << "\n";
         ++algo_count;
         try
            {
            if(!cb(vars))
               {
               std::cout << vars[name_key] << " test " << algo_count << " failed\n";
               ++algo_fail;
               }
            }
         catch(std::exception& e)
            {
            std::cout << vars[name_key] << " test " << algo_count << " failed: " << e.what() << "\n";
            ++algo_fail;
            }

         if(clear_between_cb)
            {
            vars.clear();
            vars[name_key] = fixed_name;
            }
         }
      }

   test_report(name_key, test_count, test_fails);

   return test_fails;
   }

size_t run_tests(std::istream& src,
                 const std::string& name_key,
                 const std::string& output_key,
                 bool clear_between_cb,
                 std::function<std::string (std::map<std::string, std::string>)> cb)
   {
   return run_tests_bb(src, name_key, output_key, clear_between_cb,
                [name_key,output_key,cb](std::map<std::string, std::string> vars)
                {
                const std::string got = cb(vars);
                if(got != vars[output_key])
                   {
                   std::cout << name_key << ' ' << vars[name_key] << " got " << got
                             << " expected " << vars[output_key] << std::endl;
                   return false;
                   }
                return true;
                });
   }

size_t run_all_tests()
   {
   std::vector<test_fn> all_tests;

   all_tests.push_back(test_block);
   all_tests.push_back(test_stream);
   all_tests.push_back(test_hash);
   all_tests.push_back(test_mac);

   all_tests.push_back(test_modes);

   all_tests.push_back(test_aead);
   all_tests.push_back(test_ocb);
   all_tests.push_back(test_eax);

   all_tests.push_back(test_pbkdf);
   all_tests.push_back(test_kdf);
   all_tests.push_back(test_hkdf);
   all_tests.push_back(test_keywrap);
   all_tests.push_back(test_transform);

   all_tests.push_back(test_rngs);
   all_tests.push_back(test_passhash9);
   all_tests.push_back(test_bcrypt);
   all_tests.push_back(test_cryptobox);

   all_tests.push_back(test_bigint);
   all_tests.push_back(test_pubkey);

   all_tests.push_back(test_ecc);
   all_tests.push_back(test_ecdsa);
   all_tests.push_back(test_ecdh);
   all_tests.push_back(test_pk_keygen);
   all_tests.push_back(test_cvc);
   all_tests.push_back(test_x509);
   all_tests.push_back(test_tls);

   return run_tests(all_tests);
   }
