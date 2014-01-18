#include "tests.h"
#include <botan/init.h>
#include <iostream>
#include <boost/filesystem.hpp>
#include <fstream>

namespace fs = boost::filesystem;

std::vector<std::string> list_dir(const std::string& dir_path)
   {
   std::vector<std::string> paths;

   fs::recursive_directory_iterator dir(dir_path), end;

   while (dir != end)
      {
      if(dir->path().extension().string() == ".vec")
         paths.push_back(dir->path().string());
      ++dir;
      }

   std::sort(paths.begin(), paths.end());

   return paths;
   }

size_t run_tests_in_dir(const std::string& dir, std::function<size_t (const std::string&)> fn)
   {
   size_t fails = 0;
   for(auto vec: list_dir(dir))
      fails += fn(vec);
   return fails;
   }

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
         std::cout << "Exception escaped test: " << e.what() << "\n";
         ++fails;
         }
      catch(...)
         {
         std::cout << "Exception escaped test\n";
         ++fails;
         }
      }

   test_report("Tests", 0, fails);

   return fails;
   }

void test_report(const std::string& name, size_t ran, size_t failed)
   {
   std::cout << name;

   if(ran > 0)
      std::cout << " " << ran << " tests";

   if(failed)
      std::cout << " " << failed << " FAILs\n";
   else
      std::cout << " all ok\n";
   }

size_t run_tests_bb(std::istream& src,
                    const std::string& name_key,
                    const std::string& output_key,
                    bool clear_between_cb,
                    std::function<size_t (std::map<std::string, std::string>)> cb)
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
         //std::cout << vars[name_key] << " " << algo_count << "\n";
         ++algo_count;
         try
            {
            const size_t fails = cb(vars);

            if(fails)
               {
               std::cout << vars[name_key] << " test " << algo_count << ": " << fails << " failure\n";
               algo_fail += fails;
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

   test_count += algo_count;
   test_fails += algo_fail;

   if(fixed_name != "" && (algo_count > 0 || algo_fail > 0))
      test_report(fixed_name, algo_count, algo_fail);
   else
      test_report(name_key, test_count, test_fails);

   return test_fails;
   }

size_t run_tests(const std::string& filename,
                 const std::string& name_key,
                 const std::string& output_key,
                 bool clear_between_cb,
                 std::function<std::string (std::map<std::string, std::string>)> cb)
   {
   std::ifstream vec(filename);

   if(!vec)
      {
      std::cout << "Failure opening " << filename << "\n";
      return 1;
      }

   return run_tests(vec, name_key, output_key, clear_between_cb, cb);
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
                   return 1;
                   }
                return 0;
                });
   }

namespace {

int help(char* argv0)
   {
   std::cout << "Usage: " << argv0 << " [suite]\n";
   std::cout << "Suites: all (default), block, hash, bigint, rsa, ecdsa, ...\n";
   return 1;
   }

}

int main(int argc, char* argv[])
   {
   if(argc != 1 && argc != 2)
      return help(argv[0]);

   std::string target = "all";

   if(argc == 2)
      target = argv[1];

   if(target == "-h" || target == "--help" || target == "help")
      return help(argv[0]);

   std::vector<test_fn> tests;

#define DEF_TEST(test) do { if(target == "all" || target == #test) \
      tests.push_back(test_ ## test);                              \
   } while(0)

   DEF_TEST(block);
   DEF_TEST(modes);
   DEF_TEST(aead);
   DEF_TEST(ocb);

   DEF_TEST(stream);
   DEF_TEST(hash);
   DEF_TEST(mac);
   DEF_TEST(pbkdf);
   DEF_TEST(kdf);
   DEF_TEST(hkdf);
   DEF_TEST(keywrap);
   DEF_TEST(transform);
   DEF_TEST(rngs);
   DEF_TEST(passhash9);
   DEF_TEST(bcrypt);
   DEF_TEST(cryptobox);
   DEF_TEST(tss);

   DEF_TEST(bigint);

   DEF_TEST(rsa);
   DEF_TEST(rw);
   DEF_TEST(dsa);
   DEF_TEST(nr);
   DEF_TEST(dh);
   DEF_TEST(dlies);
   DEF_TEST(elgamal);
   DEF_TEST(ecdsa);
   DEF_TEST(gost_3410);

   DEF_TEST(ecc_unit);
   DEF_TEST(ecdsa_unit);
   DEF_TEST(ecdh_unit);
   DEF_TEST(pk_keygen);
   DEF_TEST(cvc);
   DEF_TEST(x509);
   DEF_TEST(tls);

   if(tests.empty())
      {
      std::cout << "No tests selected by target '" << target << "'\n";
      return 1;
      }

   Botan::LibraryInitializer init;

   return run_tests(tests);
   }
