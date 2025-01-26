/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_OID_MAP_H_
#define BOTAN_OID_MAP_H_

#include <botan/asn1_obj.h>
#include <botan/mutex.h>
#include <string>
#include <string_view>
#include <unordered_map>

namespace Botan {

class OID_Map final {
   public:
      void add_oid(const OID& oid, std::string_view str);

      void add_str2oid(const OID& oid, std::string_view str);

      void add_oid2str(const OID& oid, std::string_view str);

      std::string oid2str(const OID& oid);

      OID str2oid(std::string_view str);

      static OID_Map& global_registry();

   private:
      static std::unordered_map<OID, std::string> load_oid2str_map();
      static std::unordered_map<std::string, OID> load_str2oid_map();

      OID_Map();

      mutex_type m_mutex;
      std::unordered_map<std::string, OID> m_str2oid;
      std::unordered_map<OID, std::string> m_oid2str;
};

}  // namespace Botan

#endif
