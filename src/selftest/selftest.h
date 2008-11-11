/*************************************************
* Startup Self Test Header File                  *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_SELF_TESTS_H__
#define BOTAN_SELF_TESTS_H__

#include <botan/algo_factory.h>

namespace Botan {

/*************************************************
* Self Tests                                     *
*************************************************/
BOTAN_DLL bool passes_self_tests(Algorithm_Factory& af);

}

#endif
