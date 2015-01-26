/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <botan/hex.h>
#include <iostream>
#include <fstream>

#if defined(BOTAN_HAS_HKDF)
#include <botan/libstate.h>
#include <botan/hkdf.h>

using namespace Botan;

namespace {

secure_vector<byte> hkdf(const std::string& hkdf_algo,
                         const secure_vector<byte>& ikm,
                         const secure_vector<byte>& salt,
                         const secure_vector<byte>& info,
                         size_t L)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   const std::string algo = hkdf_algo.substr(5, hkdf_algo.size()-6);

   const MessageAuthenticationCode* mac_proto = af.prototype_mac("HMAC(" + algo + ")");

   if(!mac_proto)
      throw std::invalid_argument("Bad HKDF hash '" + algo + "'");

   HKDF hkdf(mac_proto->clone(), mac_proto->clone());

   hkdf.start_extract(salt.data(), salt.size());
   hkdf.extract(ikm.data(), ikm.size());
   hkdf.finish_extract();

   secure_vector<byte> key(L);
   hkdf.expand(key.data(), key.size(), info.data(), info.size());
   return key;
   }

size_t hkdf_test(const std::string& algo,
               const std::string& ikm,
               const std::string& salt,
               const std::string& info,
               const std::string& okm,
               size_t L)
   {
   const std::string got = hex_encode(
      hkdf(algo,
           hex_decode_locked(ikm),
           hex_decode_locked(salt),
           hex_decode_locked(info),
           L)
      );

   if(got != okm)
      {
      std::cout << "HKDF got " << got << " expected " << okm << std::endl;
      return 1;
      }

   return 0;
   }

}
#endif

size_t test_hkdf()
   {
#if defined(BOTAN_HAS_HKDF)
   std::ifstream vec(TEST_DATA_DIR "/hkdf.vec");

   return run_tests_bb(vec, "HKDF", "OKM", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return hkdf_test(m["HKDF"], m["IKM"], m["salt"], m["info"],
                              m["OKM"], to_u32bit(m["L"]));
             });
#else
   return 0;
#endif
   }
