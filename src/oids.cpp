/*************************************************
* OID Registry Source File                       *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/oids.h>
#include <botan/libstate.h>

namespace Botan {

namespace OIDS {

/*************************************************
* Register an OID to string mapping              *
*************************************************/
void add_oid(const OID& oid, const std::string& name)
   {
   const std::string oid_str = oid.as_string();

   if(!global_state().option_set("oid2str", oid_str))
      global_state().set_option("oid2str", oid_str, name);
   if(!global_state().option_set("str2oid", name))
      global_state().set_option("str2oid", name, oid_str);
   }

/*************************************************
* Do an OID to string lookup                     *
*************************************************/
std::string lookup(const OID& oid)
   {
   return global_state().get_option("oid2str", oid.as_string());
   }

/*************************************************
* Do a string to OID lookup                      *
*************************************************/
OID lookup(const std::string& name)
   {
   return OID(global_state().get_option("str2oid", name));
   }

/*************************************************
* Check to see if an OID exists in the table     *
*************************************************/
bool have_oid(const std::string& name)
   {
   return global_state().option_set("str2oid", name);
   }

}

}
