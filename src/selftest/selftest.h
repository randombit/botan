/*
* Startup Self Test
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SELF_TESTS_H__
#define BOTAN_SELF_TESTS_H__

#include <botan/algo_factory.h>
#include <botan/scan_name.h>
#include <map>
#include <string>

namespace Botan {

/*
* Self Tests
*/
BOTAN_DLL bool passes_self_tests(Algorithm_Factory& af);

BOTAN_DLL std::map<std::string, bool>
algorithm_kat(const SCAN_Name& algo_name,
              const std::map<std::string, std::string>& vars,
              Algorithm_Factory& af);

}

#endif
