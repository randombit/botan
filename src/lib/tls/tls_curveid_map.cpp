/*
* TLS global curveid map for custom curves
* (C) 2018 Tobias Niemann
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#include <botan/tls_curveid_map.h>
#include <botan/mutex.h>
#include <botan/tls_extensions.h>

#include <map>


namespace Botan {

namespace TLS {

namespace CurveIDS{
namespace {

class Curveid_Map final
   {
   public:
      void add_curveid(const std::string name, const uint16_t curveid)
         {
         add_str2curveid(name, curveid);
         add_curveid2str(name, curveid);
         }
    
      void add_str2curveid(const std::string name, const uint16_t curveid)
         {
         if(Supported_Groups::name_to_curve_id(name) == 0)
            {
            lock_guard_type<mutex_type> lock(m_mutex);
            m_str2curveid.insert(std::make_pair(name, curveid));
            }
         }
      void add_curveid2str(const std::string name, const uint16_t curveid)
         {
         if(Supported_Groups::curve_id_to_name(curveid) == "")
            {
            lock_guard_type<mutex_type> lock(m_mutex);
            m_curveid2str.insert(std::make_pair(curveid, name));
            }
         }
      std::string lookup(const uint16_t curveid)
         {
         lock_guard_type<mutex_type> lock(m_mutex); 
         auto i = m_curveid2str.find(curveid);
         if(i != m_curveid2str.end())
            return i->second;

         return "";
         }
      
      uint16_t lookup(const std::string name)
         {
         lock_guard_type<mutex_type> lock(m_mutex); 
         auto i = m_str2curveid.find(name);
         if(i != m_str2curveid.end())
            return i->second;

         return 0;
         }
    
      static Curveid_Map& global_curveids()
         {
         static Curveid_Map curveid_map;
         return curveid_map;
         }
      
   private:
      mutex_type m_mutex;
      std::map<std::string, uint16_t> m_str2curveid;
      std::map<uint16_t, std::string> m_curveid2str;
   };
}

void add_curveid(const std::string name, const uint16_t curveid)
    {
    Curveid_Map::global_curveids().add_curveid(name, curveid);
    }

std::string lookup(const uint16_t curveid)
    {
    return Curveid_Map::global_curveids().lookup(curveid);
    }
      
uint16_t lookup(const std::string name)
    {
    return Curveid_Map::global_curveids().lookup(name);
    }

}
}
}