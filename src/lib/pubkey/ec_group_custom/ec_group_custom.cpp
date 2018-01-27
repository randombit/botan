/*
* ECC Custom Domain Parameters Registry
* (C) 2018 Tobias Niemann
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ec_group_custom.h>
#include <botan/exceptn.h>
#include <botan/parsing.h>

#if defined(BOTAN_HAS_TLS)
   #include <botan/tls_curveid_map.h>
#endif

namespace Botan {
    
namespace EC_Group_Custom {
    
namespace {
class EC_Group_Custom final
   {
   public:
      void add_curve(const std::string name, OID oid, EC_Group group, RandomNumberGenerator& rng, uint16_t curveid)
      {
      if(!group.verify_group(rng))
         throw Invalid_Argument("Custom EC_Group is invalid");

      OIDS::add_oid(oid, name);
      if(OIDS::lookup(oid) != name)
         {
         throw Invalid_Argument("Custom EC_Group OID is already in use");
         }
#if defined(BOTAN_HAS_TLS)
      if(curveid)
         {
         TLS::CurveIDS::add_curveid(name, curveid);
         if(TLS::CurveIDS::lookup(curveid) != name)
            {
            throw Invalid_Argument("Custom EC_Groups CurveID is already in use");
            }
         }
#endif
      lock_guard_type<mutex_type> lock(m_mutex);
      auto ret = m_groups.insert(std::make_pair(name, group));
      if(!ret.second)
         {
         throw Invalid_Argument("EC_Group name is already taken");
         }
          }
      
      EC_Group get_group(const std::string& name)
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         auto i = m_groups.find(name);
         if(i != m_groups.end())
            return i->second;

         return EC_Group();
         }

      static EC_Group_Custom& global_custom_curves()
         {
         static EC_Group_Custom ec_map;
         return ec_map;
         }
   private:
      mutex_type m_mutex;
      std::map<std::string, EC_Group> m_groups;

   };        
}

void add_curve(const std::string name, OID oid, EC_Group group, RandomNumberGenerator& rng,
                                uint16_t curveid)
   {
   EC_Group_Custom::global_custom_curves().add_curve(name, oid, group, rng, curveid);
   }

void add_curve(const std::string name, OID oid, BigInt p, BigInt a, BigInt b, BigInt x, BigInt y,
                                BigInt order,
                                BigInt cofactor, RandomNumberGenerator& rng, uint16_t curveid)
   {
   CurveGFp curve(p, a, b);
   PointGFp basepoint(curve, x, y);

   EC_Group group(curve, basepoint, order, cofactor);

   add_curve(name, oid, group, rng, curveid); 
   }

EC_Group get_group(const std::string& name)
   {
   return EC_Group_Custom::global_custom_curves().get_group(name);
   }

}

EC_Group_Text::EC_Group_Text(const std::string& s)
   {
   std::istringstream iss(s);

   m_kv = read_cfg(iss);
   }

EC_Group_Text::EC_Group_Text(std::istream& in) : m_kv(read_cfg(in))
   {}

BigInt EC_Group_Text::get_req_bn(const std::string& key, std::map<std::string, std::string>& kv)
   {
   auto i = kv.find(key);
   if(i == kv.end())
      {
      throw Invalid_Argument("EC_Group_Text missing paramater " + key);
      }

   try
      {
      return BigInt(i->second);
      }
   catch(std::exception&)
      {
      throw Invalid_Argument("EC_Group_Text invalid BigInt input '" + i->second + "'" +
                             + " for key " + key);
      }
   }

uint16_t EC_Group_Text::get_opt_u16(const std::string& key, std::map<std::string, std::string>& kv)
   {
   auto i = kv.find(key);
   if(i == kv.end())
      {
      return 0;
      }
   uint32_t num_32;
   try
      {
      num_32 = BigInt(i->second).to_u32bit();
      }
   catch(std::exception&)
      {
      throw Invalid_Argument("EC_Group_Text invalid BigInt input '" + i->second + "'" +
                             + " for key " + key);
      }
   if(num_32 > 0xFFFF)
      throw Invalid_Argument("EC_Group_Text invalid input '" + i->second + "'" +
                             + " for key " + key);
   return num_32;

   }

std::string EC_Group_Text::get_req_str(const std::string& key, std::map<std::string, std::string>& kv)
   {
   auto i = kv.find(key);
   if(i == kv.end())
      {
      throw Invalid_Argument("EC_Group_Text missing paramater " + key);
      }

   return i->second;
   }

void EC_Group_Text::add_curve(RandomNumberGenerator& rng, std::map<std::string, std::string>& kv)
   {
   std::string name = get_req_str("name",kv);
   OID oid(get_req_str("oid",kv));
   uint16_t curveid = get_opt_u16("curveid",kv);

   BigInt p = get_req_bn("prime",kv);
   BigInt a = get_req_bn("a", kv);
   BigInt b = get_req_bn("b",kv);

   BigInt x = get_req_bn("x",kv);
   BigInt y = get_req_bn("y",kv);

   BigInt order = get_req_bn("order",kv);
   BigInt cofactor = get_req_bn("cofactor",kv);

   Botan::EC_Group_Custom::add_curve(name, oid, p, a, b, x, y, order, cofactor, rng, curveid);
   }

void EC_Group_Text::add_curves(RandomNumberGenerator& rng)
   {
   for(auto& i : m_kv)
      {
      add_curve(rng, i);
      }
   }

std::vector<std::map<std::string, std::string> > EC_Group_Text::read_cfg(std::istream& is)
   {
   std::vector<std::map<std::string, std::string>> kvv;
   std::map<std::string, std::string> kv;
   size_t line = 0;
   while(is.good())
      {
      std::string s;

      std::getline(is, s);

      ++line;

      if(s.empty() || s[0] == '#')
         continue;

      s = clean_ws(s.substr(0, s.find('#')));

      if(s.empty())
         continue;


      if(s[0] == '[' && s[s.size()-1] == ']')
         {
         if(!kv.empty())
            {
            kvv.push_back(kv);
            }
         kv.clear();
         kv.insert(std::make_pair("name",s.substr(1, s.size() - 2)));
         continue;
         }


      auto eq = s.find("=");

      if(eq == std::string::npos || eq == 0 || eq == s.size() - 1)
         throw Exception("Bad read_cfg input '" + s + "' on line " + std::to_string(line));

      const std::string key = clean_ws(s.substr(0, eq));
      const std::string val = clean_ws(s.substr(eq + 1, std::string::npos));

      auto ret = kv.insert(std::make_pair(key, val));
      if(!ret.second)
         {
         throw Invalid_Argument("Duplicate ECC_Custom Text parameters");
         }
      }
   if(!kv.empty())
      {
      kvv.push_back(kv);
      }
   return kvv;
   }
}