/*
* OID Registry
* (C) 1999-2008,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/oids.h>
#include <botan/mutex.h>

namespace Botan {

namespace OIDS {

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
            m_str2oid.insert(std::make_pair(str, oid.as_string()));
         }

      void add_oid2str(const OID& oid, const std::string& str)
         {
         const std::string oid_str = oid.as_string();
         lock_guard_type<mutex_type> lock(m_mutex);
         auto i = m_oid2str.find(oid_str);
         if(i == m_oid2str.end())
            m_oid2str.insert(std::make_pair(oid_str, str));
         }

      std::string lookup(const OID& oid)
         {
         const std::string oid_str = oid.as_string();

         lock_guard_type<mutex_type> lock(m_mutex);

         auto i = m_oid2str.find(oid_str);
         if(i != m_oid2str.end())
            return i->second;

         return "";
         }

      OID lookup(const std::string& str)
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
         m_str2oid = load_str2oid_map();
         m_oid2str = load_oid2str_map();
         }

      mutex_type m_mutex;
      std::unordered_map<std::string, OID> m_str2oid;
      std::unordered_map<std::string, std::string> m_oid2str;
   };

}

void add_oid(const OID& oid, const std::string& name)
   {
   OID_Map::global_registry().add_oid(oid, name);
   }

void add_oidstr(const char* oidstr, const char* name)
   {
   add_oid(OID(oidstr), name);
   }

void add_oid2str(const OID& oid, const std::string& name)
   {
   OID_Map::global_registry().add_oid2str(oid, name);
   }

void add_str2oid(const OID& oid, const std::string& name)
   {
   OID_Map::global_registry().add_str2oid(oid, name);
   }

std::string lookup(const OID& oid)
   {
   return OID_Map::global_registry().lookup(oid);
   }

OID lookup(const std::string& name)
   {
   return OID_Map::global_registry().lookup(name);
   }

bool have_oid(const std::string& name)
   {
   return OID_Map::global_registry().have_oid(name);
   }

bool name_of(const OID& oid, const std::string& name)
   {
   return (oid == lookup(name));
   }

}

}
