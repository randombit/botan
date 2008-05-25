/*************************************************
* PK Key Types Source File                       *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/pk_keys.h>
#include <botan/config.h>
#include <botan/oids.h>
#include <botan/x509_key.h>
#include <botan/pkcs8.h>

namespace Botan {

namespace {

/*************************************************
* Find out how much testing should be performed  *
*************************************************/
bool key_check_level(const std::string& type)
   {
   const std::string setting = global_config().option("pk/test/" + type);
   if(setting == "basic")
      return false;
   return true;
   }

}

/*************************************************
* Factories for Public Key x509 En-/Decoder      *
*************************************************/

std::auto_ptr<X509_Encoder> Public_Key::x509_encoder() const 
   { 
   return std::auto_ptr<X509_Encoder>(); 
   }

std::auto_ptr<X509_Decoder> Public_Key::x509_decoder() 
   { 
   return std::auto_ptr<X509_Decoder>(); 
   }


/*************************************************
* Factories for Private Key PKCS8 En-/Decoder    *
*************************************************/

std::auto_ptr<PKCS8_Encoder> Private_Key::pkcs8_encoder() const 
   { 
   return std::auto_ptr<PKCS8_Encoder>(); 
   }

std::auto_ptr<PKCS8_Decoder> Private_Key::pkcs8_decoder() 
   { 
   return std::auto_ptr<PKCS8_Decoder>(); 
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
void Public_Key::load_check() const
   {
   if(!check_key(key_check_level("public")))
      throw Invalid_Argument(algo_name() + ": Invalid public key");
   }

/*************************************************
* Run checks on a loaded private key             *
*************************************************/
void Private_Key::load_check() const
   {
   if(!check_key(key_check_level("private")))
      throw Invalid_Argument(algo_name() + ": Invalid private key");
   }

/*************************************************
* Run checks on a generated private key          *
*************************************************/
void Private_Key::gen_check() const
   {
   if(!check_key(key_check_level("private_gen")))
      throw Self_Test_Failure(algo_name() + " private key generation failed");
   }

}
