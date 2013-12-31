/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <iostream>
#include <string>
#include <botan/cpuid.h>

using namespace Botan;

int main()
   {
   CPUID::initialize();

   CPUID::print(std::cout);
   }
