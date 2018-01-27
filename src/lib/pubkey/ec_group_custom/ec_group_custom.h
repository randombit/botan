/*
* ECC Custom Domain Parameters Registry
* (C) 2018 Tobias Niemann
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EC_GROUP_CUSTOM_H_
#define BOTAN_EC_GROUP_CUSTOM_H_

#include <botan/oids.h>
#include <botan/bigint.h>
#include <botan/rng.h>
#include <botan/ec_group.h>
#include <botan/mutex.h>

#include <map>
#include <sstream>

namespace Botan {
    
namespace EC_Group_Custom {

BOTAN_UNSTABLE_API void add_curve(const std::string name, OID oid, EC_Group group, RandomNumberGenerator& rng,
                                uint16_t curveid);

BOTAN_UNSTABLE_API void add_curve(const std::string name, OID oid, BigInt p, BigInt a, BigInt b, BigInt x, BigInt y,
                                BigInt order,
                                BigInt cofactor, RandomNumberGenerator& rng, uint16_t curveid);

BOTAN_UNSTABLE_API EC_Group get_group(const std::string& name);
}

class BOTAN_UNSTABLE_API EC_Group_Text final
   {
   public:
      EC_Group_Text(const std::string& s);
      EC_Group_Text(std::istream& in);
      void add_curves(RandomNumberGenerator& rng);

   private:
      BigInt get_req_bn(const std::string& key, std::map<std::string, std::string>& kv);
      std::string get_req_str(const std::string& key, std::map<std::string, std::string>& kv);
      uint16_t get_opt_u16(const std::string& key, std::map<std::string, std::string>& kv);

      void add_curve(RandomNumberGenerator& rng, std::map<std::string, std::string>& kv);
      std::vector<std::map<std::string, std::string> > m_kv;
      std::vector<std::map<std::string, std::string> > read_cfg(std::istream& is);
   };

}

#endif

