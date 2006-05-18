/*
  A minimal FIPS-140 application.

  Written by Jack Lloyd (lloyd@randombit.net), on December 16-19, 2003

  This file is in the public domain
*/

#include <botan/botan.h>
#include <botan/fips140.h>
using namespace Botan;

#include <iostream>
#include <fstream>

int main(int, char* argv[])
   {
   const std::string EDC_SUFFIX = ".edc";

   try {
      LibraryInitializer init; /* automatically does startup self tests */

      // you can also do self tests on demand, like this:
      if(!FIPS140::passes_self_tests())
         throw Self_Test_Failure("FIPS-140 startup tests");

      /*
        Here, we just check argv[0] and assume that it works. You can use
        various extremely nonportable APIs on some Unices (dladdr, to name one)
        to find out the real name (I presume there are similiarly hairy ways of
        doing it on Windows). We then assume the EDC (Error Detection Code, aka
        a hash) is stored in argv[0].edc

        Remember: argv[0] can be easily spoofed. Don't trust it for real.

        You can also do various nasty things and find out the path of the
        shared library you are linked with, and check that hash.
      */
      std::string exe_path = argv[0];
      std::string edc_path = exe_path + EDC_SUFFIX;
      std::ifstream edc_file(edc_path.c_str());
      std::string edc;
      std::getline(edc_file, edc);

      std::cout << "Our EDC is " << edc << std::endl;

      bool good = FIPS140::good_edc(exe_path, edc);

      if(good)
         std::cout << "Our EDC matches" << std::endl;
      else
         std::cout << "Our EDC is bad" << std::endl;
   }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      }
   return 0;
   }
