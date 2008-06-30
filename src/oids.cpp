/*************************************************
* OID Registry Source File                       *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/oids.h>
#include <botan/config.h>
#include <botan/libstate.h>

namespace Botan {

namespace OIDS {

/*************************************************
* Register an OID to string mapping              *
*************************************************/
void add_oid(const OID& oid, const std::string& name)
   {
   const std::string oid_str = oid.as_string();

   if(!global_state().config().is_set("oid2str", oid_str))
      global_state().config().set("oid2str", oid_str, name);
   if(!global_state().config().is_set("str2oid", name))
      global_state().config().set("str2oid", name, oid_str);
   }

/*************************************************
* Do an OID to string lookup                     *
*************************************************/
std::string lookup(const OID& oid)
   {
   std::string name = global_state().config().get("oid2str", oid.as_string());
   if(name == "")
      return oid.as_string();
   return name;
   }

/*************************************************
* Do a string to OID lookup                      *
*************************************************/
OID lookup(const std::string& name)
   {
   std::string value = global_state().config().get("str2oid", name);
   if(value != "")
      return OID(value);

   try
      {
      return OID(name);
      }
   catch(Exception)
      {
      throw Lookup_Error("No object identifier found for " + name);
      }
   }

/*************************************************
* Check to see if an OID exists in the table     *
*************************************************/
bool have_oid(const std::string& name)
   {
   return global_state().config().is_set("str2oid", name);
   }

/*************************************************
* Check to see if an OID exists in the table     *
*************************************************/
bool name_of(const OID& oid, const std::string& name)
   {
   return (oid == lookup(name));
   }

}

}
