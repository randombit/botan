#include "validate.h"

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

void hkdf_test(const std::string& algo,
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
   }

}

void test_hkdf()
   {
   // From RFC 5869
   std::ifstream vec("checks/hkdf.vec");

   std::map<std::string, std::string> vars;

   while(vec.good())
      {
      std::string line;
      std::getline(vec, line);

      if(line == "")
         continue;

      const std::string key = line.substr(0, line.find_first_of(' '));
      const std::string val = line.substr(line.find_last_of(' ') + 1, std::string::npos);

      vars[key] = val;

      if(key == "OKM")
         {
         hkdf_test(vars["Hash"], vars["IKM"], vars["salt"], vars["info"],
                   vars["OKM"], to_u32bit(vars["L"]));
         vars.clear();
         }
      }
   }
