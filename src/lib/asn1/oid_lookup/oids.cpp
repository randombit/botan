/*
* OID Registry
* (C) 1999-2008,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/oids.h>
#include <mutex>

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
         std::lock_guard<std::mutex> lock(m_mutex);
         auto i = m_str2oid.find(str);
         if(i == m_str2oid.end())
            m_str2oid.insert(std::make_pair(str, oid));
         }

      void add_oid2str(const OID& oid, const std::string& str)
         {
         std::lock_guard<std::mutex> lock(m_mutex);
         auto i = m_oid2str.find(oid);
         if(i == m_oid2str.end())
            m_oid2str.insert(std::make_pair(oid, str));
         }

      std::string lookup(const OID& oid)
         {
         std::lock_guard<std::mutex> lock(m_mutex);

         auto i = m_oid2str.find(oid);
         if(i != m_oid2str.end())
            return i->second;

         return "";
         }

      OID lookup(const std::string& str)
         {
         std::lock_guard<std::mutex> lock(m_mutex);

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
         std::lock_guard<std::mutex> lock(m_mutex);
         return m_str2oid.find(str) != m_str2oid.end();
         }

   private:
      std::mutex m_mutex;
      std::map<std::string, OID> m_str2oid;
      std::map<OID, std::string> m_oid2str;
   };

OID_Map& global_oid_map()
   {
   static OID_Map map;
   return map;
   }

}

void add_oid(const OID& oid, const std::string& name)
   {
   global_oid_map().add_oid(oid, name);
   }

void add_oidstr(const char* oidstr, const char* name)
   {
   add_oid(OID(oidstr), name);
   }

void add_oid2str(const OID& oid, const std::string& name)
   {
   global_oid_map().add_oid2str(oid, name);
   }

void add_str2oid(const OID& oid, const std::string& name)
   {
   global_oid_map().add_oid2str(oid, name);
   }

std::string lookup(const OID& oid)
   {
   return global_oid_map().lookup(oid);
   }

OID lookup(const std::string& name)
   {
   return global_oid_map().lookup(name);
   }

bool have_oid(const std::string& name)
   {
   return global_oid_map().have_oid(name);
   }

bool name_of(const OID& oid, const std::string& name)
   {
   return (oid == lookup(name));
   }

}

}
