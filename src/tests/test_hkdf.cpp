#include "tests.h"

#include <botan/libstate.h>
#include <botan/hkdf.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

secure_vector<byte> hkdf(const std::string& algo,
                         const secure_vector<byte>& ikm,
                         const secure_vector<byte>& salt,
                         const secure_vector<byte>& info,
                         size_t L)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();
   const MessageAuthenticationCode* mac_proto = af.prototype_mac("HMAC(" + algo + ")");

   if(!mac_proto)
      throw std::invalid_argument("Bad HKDF hash " + algo);

   HKDF hkdf(mac_proto->clone(), mac_proto->clone());

   hkdf.start_extract(&salt[0], salt.size());
   hkdf.extract(&ikm[0], ikm.size());
   hkdf.finish_extract();

   secure_vector<byte> key(L);
   hkdf.expand(&key[0], key.size(), &info[0], info.size());
   return key;
   }

bool hkdf_test(const std::string& algo,
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
      std::cout << "HKDF got " << got << " expected " << okm << std::endl;

   return (got == okm);
   }

}

size_t test_hkdf()
   {
   // From RFC 5869
   std::ifstream vec(CHECKS_DIR "/hkdf.vec");

   return run_tests_bb(vec, "HKDF", "OKM", true,
             [](std::map<std::string, std::string> m) -> bool
             {
             return hkdf_test(m["Hash"], m["IKM"], m["salt"], m["info"],
                              m["OKM"], to_u32bit(m["L"]));
             });
   }
