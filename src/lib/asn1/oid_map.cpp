/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/oid_map.h>

namespace Botan {

OID_Map::OID_Map() {
   m_str2oid = OID_Map::load_str2oid_map();
   m_oid2str = OID_Map::load_oid2str_map();
}

OID_Map& OID_Map::global_registry() {
   static OID_Map g_map;
   return g_map;
}

void OID_Map::add_oid(const OID& oid, std::string_view str) {
   lock_guard_type<mutex_type> lock(m_mutex);

   auto o2s = m_oid2str.find(oid);

   if(o2s == m_oid2str.end()) {
      m_oid2str.insert(std::make_pair(oid, str));
   } else if(o2s->second != str) {
      throw Invalid_State("Cannot register two different names to a single OID");
   }

   auto s2o = m_str2oid.find(std::string(str));

   if(s2o == m_str2oid.end()) {
      m_str2oid.insert(std::make_pair(str, oid));
   }
}

void OID_Map::add_str2oid(const OID& oid, std::string_view str) {
   lock_guard_type<mutex_type> lock(m_mutex);
   if(!m_str2oid.contains(std::string(str))) {
      m_str2oid.insert(std::make_pair(str, oid));
   }
}

void OID_Map::add_oid2str(const OID& oid, std::string_view str) {
   lock_guard_type<mutex_type> lock(m_mutex);
   if(!m_oid2str.contains(oid)) {
      m_oid2str.insert(std::make_pair(oid, str));
   }
}

std::string OID_Map::oid2str(const OID& oid) {
   lock_guard_type<mutex_type> lock(m_mutex);

   auto i = m_oid2str.find(oid);
   if(i != m_oid2str.end()) {
      return i->second;
   }

   return "";
}

OID OID_Map::str2oid(std::string_view str) {
   lock_guard_type<mutex_type> lock(m_mutex);
   auto i = m_str2oid.find(std::string(str));
   if(i != m_str2oid.end()) {
      return i->second;
   }

   return OID();
}

}  // namespace Botan
