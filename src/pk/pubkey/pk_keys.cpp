/*************************************************
* PK Key Types Source File                       *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/pk_keys.h>
#include <botan/libstate.h>
#include <botan/oids.h>

namespace Botan {

namespace {

/*************************************************
* Find out how much testing should be performed  *
*************************************************/
bool key_check_level(const std::string& type)
   {
   const std::string setting = global_state().option("pk/test/" + type);
   if(setting == "basic")
      return false;
   return true;
   }

}

/*************************************************
* Default OID access                             *
*************************************************/
OID Public_Key::get_oid() const
   {
   try {
      return OIDS::lookup(algo_name());
      }
   catch(Lookup_Error)
      {
      throw Lookup_Error("PK algo " + algo_name() + " has no defined OIDs");
      }
   }

/*************************************************
* Run checks on a loaded public key              *
*************************************************/
void Public_Key::load_check(RandomNumberGenerator& rng) const
   {
   if(!check_key(rng, key_check_level("public")))
      throw Invalid_Argument(algo_name() + ": Invalid public key");
   }

/*************************************************
* Run checks on a loaded private key             *
*************************************************/
void Private_Key::load_check(RandomNumberGenerator& rng) const
   {
   if(!check_key(rng, key_check_level("private")))
      throw Invalid_Argument(algo_name() + ": Invalid private key");
   }

/*************************************************
* Run checks on a generated private key          *
*************************************************/
void Private_Key::gen_check(RandomNumberGenerator& rng) const
   {
   if(!check_key(rng, key_check_level("private_gen")))
      throw Self_Test_Failure(algo_name() + " private key generation failed");
   }

}
