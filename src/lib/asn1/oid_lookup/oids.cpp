/*
* OID Registry
* (C) 1999-2008,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/oids.h>
#include <botan/parsing.h>
#include <botan/mutex.h>
#include <sstream>

namespace Botan {

namespace OIDS {

namespace {

class OID_Map
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
         lock_guard_type<mutex_type> lock(m_mutex);
         auto i = m_oid2str.find(oid);
         if(i == m_oid2str.end())
            m_oid2str.insert(std::make_pair(oid, str));
         }

      std::string lookup(const OID& oid)
         {
         lock_guard_type<mutex_type> lock(m_mutex);

         auto i = m_oid2str.find(oid);
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

         // Try to parse as plain OID
         try
            {
            return OID(str);
            }
         catch(...) {}

         throw Lookup_Error("No object identifier found for " + str);
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

      void read_cfg(std::istream& cfg, const std::string& source);

   private:

      OID_Map()
         {
         std::istringstream cfg(default_oid_list());
         read_cfg(cfg, "builtin");
         }

      mutex_type m_mutex;
      std::map<std::string, OID> m_str2oid;
      std::map<OID, std::string> m_oid2str;
   };

void OID_Map::read_cfg(std::istream& cfg, const std::string& source)
   {
   lock_guard_type<mutex_type> lock(m_mutex);

   size_t line = 0;

   while(cfg.good())
      {
      std::string s;
      std::getline(cfg, s);
      ++line;

      if(s.empty() || s[0] == '#')
         continue;

      s = clean_ws(s.substr(0, s.find('#')));

      if(s.empty())
         continue;

      auto eq = s.find("=");

      if(eq == std::string::npos || eq == 0 || eq == s.size() - 1)
         throw Exception("Bad config line '" + s + "' in " + source + " line " + std::to_string(line));

      const std::string oid = clean_ws(s.substr(0, eq));
      const std::string name = clean_ws(s.substr(eq + 1, std::string::npos));

      m_str2oid.insert(std::make_pair(name, OID(oid)));
      m_oid2str.insert(std::make_pair(OID(oid), name));
      }
   }

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
