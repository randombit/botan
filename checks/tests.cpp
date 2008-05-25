/******************************************************
* Main unit test source file. Include other unit      *
* tests here                                          *
*                                                     *
* (C) 2007 Manuel Hartl                               *
*          hartl@flexsecure.de                        *
******************************************************/

#define BOOST_AUTO_TEST_MAIN
#include <boost/test/auto_unit_test.hpp>
#include <boost/test/included/unit_test_framework.hpp>
#include <boost/test/test_tools.hpp>
#include <vector>
#include <string>
#include <botan/botan.h>
#include <botan/types.h>
#include <botan/secmem.h>
#include <botan/exceptn.h>
#include <botan/tr1_mem_includer.h>
#include <time.h>
#include <stdio.h>

#include <botan/math/ec/point_gfp.h>
#include <botan/math/ec/curve_gfp.h>
#include <botan/math/gf/gfp_element.h>
#include <botan/ec.h>
#include <botan/ec_dompar.h>
#include <botan/x509cert.h>
#include <botan/x509self.h>
#include <botan/oids.h>
#include <botan/rsa.h>


using namespace std;
using boost::unit_test::test_suite;

string hex_encode(const Botan::byte in[], Botan::u32bit len);
Botan::SecureVector<Botan::byte> decode_hex(const string&);


//#include "hex_tests.cpp"
#include "ec_tests.cpp"
#include "gfp_Element_tests.cpp"
#include "ec_x509_tests.cpp"

// random number generators
#include "bbs_tests.cpp"
#include "sha1prng_tests.cpp"

// macs
#include "cbcmac_tests.cpp"

// sym ciphers

// asym ciphers
#include "ecdsa_tests.cpp"

// key agreement
#include "dh_tests.cpp"
#include "eckaeg_tests.cpp"

// cv certificates
#include "cvc_tests.cpp"

// multithreading
#include "thread_tests.cpp"

//countermeasures
#include "aada_test.cpp"

// performance
//#include "timing_tests.cpp"
//#include "pointmult_benchmark_tests.cpp"
