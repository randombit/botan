/* 
 * File:   main.cpp
 * Author: Juraj Somorovsky - juraj.somorovsky@hackmanit.de
 * 
 */

#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/system_rng.h>
#include <botan/hex.h>
#include <botan/rng.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <botan/numthry.h>


#include "TimingTest.h"

/**
 * Reads directory and outputs a vector of files. 
 * 
 * @param dir_path
 * @return 
 */
std::vector<std::string> read_dir(const std::string& dir_path)
   {
   DIR *dir;
   struct dirent *ent;
   std::vector<std::string> out;
   if ((dir = opendir(dir_path.c_str())) != NULL) 
      {
      while ((ent = readdir(dir)) != NULL) 
         {
         const std::string filename = ent->d_name;
         if (filename == "." || filename == "..")
            {
            continue;
            }
         const std::string full_path = dir_path + "/" + filename;
         out.push_back(full_path);
         }
      closedir(dir);
      }
   return out;
   }

/*
 * Reads vectors from a given file 
 * 
 */
std::vector<std::string> read_vectors(const std::string& filename)
   {
   std::string line;
   std::ifstream infile(filename);
   std::vector<std::string> out;
   while (std::getline(infile, line)) 
      {
      if (line.at(0) != '#') 
         {
         out.push_back(line);
         }
      }
   return out;
   }

bool executeEvaluationWithFile(std::string test, std::string filename, std::string arg)
   {
   if ((arg == "" || test.find(arg) != std::string::npos) &&
       (filename.find(test) != std::string::npos)) 
      {
      return true;
      }
   return false;
   }

int main(int argc, char* argv[])
   {
   std::vector<std::string> files = read_dir("data");
   std::string test_arg;
   if(argc < 2) 
      {
      test_arg = "";
      }
   else 
      {
      test_arg = argv[1];
      }
   for (auto const& file : files) 
      {
      std::vector<std::string> inputs = read_vectors(file);

      if (executeEvaluationWithFile("bleichenbacher", file, test_arg)) 
         {
         std::string result_folder = "results/bleichenbacher";
         std::unique_ptr<BleichenbacherTest> test(new BleichenbacherTest(inputs, result_folder, 2048));
         test->execute_evaluation();
         } 
      else if (executeEvaluationWithFile("manger", file, test_arg)) 
         {
         std::string result_folder = "results/manger";
         std::unique_ptr<MangerTest> test(new MangerTest(inputs, result_folder, 2048));
         test->execute_evaluation();
         } 
      else if (executeEvaluationWithFile("lucky13sec3", file, test_arg)) 
         {
         std::string result_folder_sha1 = "results/lucky13sha1sec3";
         std::unique_ptr<Lucky13Test> test_sha1(new Lucky13Test(inputs, result_folder_sha1, "SHA-1", 20));
         test_sha1->execute_evaluation();
         std::string result_folder_sha256 = "results/lucky13sha256sec3";
         std::unique_ptr<Lucky13Test> test_sha256(new Lucky13Test(inputs, result_folder_sha256, "SHA-256", 32));
         test_sha256->execute_evaluation();
         }
      else if (executeEvaluationWithFile("lucky13sec4sha1", file, test_arg)) 
         {
         std::string result_folder_sha1 = "results/lucky13sha1sec4";
         std::unique_ptr<Lucky13Test> test_sha1(new Lucky13Test(inputs, result_folder_sha1, "SHA-1", 20));
         test_sha1->execute_evaluation();
         }
      else if (executeEvaluationWithFile("lucky13sec4sha256", file, test_arg)) 
         {
         std::string result_folder_sha256 = "results/lucky13sha256sec4";
         std::unique_ptr<Lucky13Test> test_sha256(new Lucky13Test(inputs, result_folder_sha256, "SHA-256", 32));
         test_sha256->execute_evaluation();
         } 
      else if (executeEvaluationWithFile("lucky13sha384", file, test_arg)) 
         {
         std::string result_folder_sha384 = "results/lucky13sha384";
         std::unique_ptr<Lucky13Test> test_sha384(new Lucky13Test(inputs, result_folder_sha384, "SHA-384", 48));
         test_sha384->execute_evaluation();
         }
      else if (executeEvaluationWithFile("ecdsa", file, test_arg)) 
         {
         std::string result_folder_ecdsa = "results/ecdsa";
         std::unique_ptr<ECDSATest> test_ecdsa(new ECDSATest(inputs, result_folder_ecdsa, "secp384r1"));
         test_ecdsa->execute_evaluation();
         } 
      else 
         {
         std::cout << "\nSkipping the following test: " << file;
         }
      }

   return 1;
   }
