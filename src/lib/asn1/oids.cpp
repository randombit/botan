/*
* OID Registry
* (C) 1999-2008,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/oids.h>
#include <botan/mutex.h>

namespace Botan {

namespace {

class OID_Map final
   {
   public:
      void add_oid(const OID& oid, const std::string& str)
         {
         add_str2oid(oid, str);
         add_oid2str(oid, str);
         }

      void add_str2oid(const OID& oid, const std::string& str)
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         auto i = m_str2oid.find(str);
         if(i == m_str2oid.end())
            m_str2oid.insert(std::make_pair(str, oid));
         }

      void add_oid2str(const OID& oid, const std::string& str)
         {
         const std::string oid_str = oid.to_string();
         lock_guard_type<mutex_type> lock(m_mutex);
         auto i = m_oid2str.find(oid_str);
         if(i == m_oid2str.end())
            m_oid2str.insert(std::make_pair(oid_str, str));
         }

      std::string oid2str(const OID& oid)
         {
         const std::string oid_str = oid.to_string();

         lock_guard_type<mutex_type> lock(m_mutex);

         auto i = m_oid2str.find(oid_str);
         if(i != m_oid2str.end())
            return i->second;

         return "";
         }

      OID str2oid(const std::string& str)
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         auto i = m_str2oid.find(str);
         if(i != m_str2oid.end())
            return i->second;

         return OID();
         }

      bool have_oid(const std::string& str)
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         return m_str2oid.find(str) != m_str2oid.end();
         }

      static OID_Map& global_registry()
         {
         static OID_Map g_map;
         return g_map;
         }

   private:

      OID_Map()
         {
         m_str2oid = OIDS::load_str2oid_map();
         m_oid2str = OIDS::load_oid2str_map();
         }

      mutex_type m_mutex;
      std::unordered_map<std::string, OID> m_str2oid;
      std::unordered_map<std::string, std::string> m_oid2str;
   };

}

void OIDS::add_oid(const OID& oid, const std::string& name)
   {
   OID_Map::global_registry().add_oid(oid, name);
   }

void OIDS::add_oidstr(const char* oidstr, const char* name)
   {
   add_oid(OID(oidstr), name);
   }

void OIDS::add_oid2str(const OID& oid, const std::string& name)
   {
   OID_Map::global_registry().add_oid2str(oid, name);
   }

void OIDS::add_str2oid(const OID& oid, const std::string& name)
   {
   OID_Map::global_registry().add_str2oid(oid, name);
   }

std::string OIDS::oid2str_or_empty(const OID& oid)
   {
   return OID_Map::global_registry().oid2str(oid);
   }

OID OIDS::str2oid_or_empty(const std::string& name)
   {
   return OID_Map::global_registry().str2oid(name);
   }

std::string OIDS::oid2str_or_throw(const OID& oid)
   {
   const std::string s = OIDS::oid2str_or_empty(oid);
   if(s.empty())
      throw Lookup_Error("No name associated with OID " + oid.to_string());
   return s;
   }

bool OIDS::have_oid(const std::string& name)
   {
   return OID_Map::global_registry().have_oid(name);
   }

}
