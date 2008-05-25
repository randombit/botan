/*************************************************
* PK Key Source File                             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/pk_algs.h>
#include <botan/rsa.h>
#include <botan/dh.h>
#include <botan/ec.h>

namespace Botan {

/*************************************************
* Get an PK public key object                    *
*************************************************/
std::auto_ptr<Public_Key> get_public_key(const std::string& alg_name)
   {
   if(alg_name == "RSA")      return std::auto_ptr<Public_Key>(new RSA_PublicKey);
   else if(alg_name == "DH")  return std::auto_ptr<Public_Key>(new DH_PublicKey);
   else if(alg_name == "ECDSA") return std::auto_ptr<Public_Key>(new ECDSA_PublicKey);
   else
      return std::auto_ptr<Public_Key>();
   }

/*************************************************
* Get an PK private key object                   *
*************************************************/
std::auto_ptr<Private_Key> get_private_key(const std::string& alg_name)
   {
   if(alg_name == "RSA")      return std::auto_ptr<Private_Key>(new RSA_PrivateKey);
   else if(alg_name == "DH")  return std::auto_ptr<Private_Key>(new DH_PrivateKey);
   else if(alg_name == "ECDSA") return std::auto_ptr<Private_Key>(new ECDSA_PrivateKey);
   else
      return std::auto_ptr<Private_Key>();
   }

}
