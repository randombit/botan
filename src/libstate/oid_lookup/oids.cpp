/*
* OID Registry
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/oids.h>
#include <botan/libstate.h>

namespace Botan {

namespace OIDS {

/*
* Register an OID to string mapping
*/
void add_oid(const OID& oid, const std::string& name)
   {
   const std::string oid_str = oid.as_string();

   if(!global_state().is_set("oid2str", oid_str))
      global_state().set("oid2str", oid_str, name);
   if(!global_state().is_set("str2oid", name))
      global_state().set("str2oid", name, oid_str);
   }

/*
* Do an OID to string lookup
*/
std::string lookup(const OID& oid)
   {
   std::string name = global_state().get("oid2str", oid.as_string());
   if(name == "")
      return oid.as_string();
   return name;
   }

/*
* Do a string to OID lookup
*/
OID lookup(const std::string& name)
   {
   std::string value = global_state().get("str2oid", name);
   if(value != "")
      return OID(value);

   try
      {
      return OID(name);
      }
   catch(...)
      {
      throw Lookup_Error("No object identifier found for " + name);
      }
   }

/*
* Check to see if an OID exists in the table
*/
bool have_oid(const std::string& name)
   {
   return global_state().is_set("str2oid", name);
   }

/*
* Check to see if an OID exists in the table
*/
bool name_of(const OID& oid, const std::string& name)
   {
   return (oid == lookup(name));
   }

}

}
