#include <botan/botan.h>
#include <botan/x509self.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/ec.h>
#include <botan/look_pk.h>
using namespace Botan;

#include <iostream>
#include <fstream>

int main()
   {

   LibraryInitializer init;

   bool do_CA = true;

   try {
   	
   	  EC_Domain_Params dom_pars = global_config().get_ec_dompar("1.3.132.0.8");
	
	  ECDSA_PrivateKey key = ECDSA_PrivateKey(dom_pars);   	
	  //RSA_PrivateKey key(1024);
      //DSA_PrivateKey key(DL_Group("dsa/jce/1024"));

      std::ofstream priv_key("private.pem");
      priv_key << PKCS8::PEM_encode(key);

      X509_Cert_Options opts;

      opts.common_name = "Test CA";
      opts.country = "DE";
      opts.organization = "FlexSecure";
      opts.email = "test@test.de";
      /* Fill in other values of opts here */

      //opts.xmpp = "lloyd@randombit.net";

      if(do_CA)
         opts.CA_key();

      X509_Certificate cert = X509::create_self_signed_cert(opts, key);

      std::ofstream cert_file("insito_ec.pem");
      cert_file << cert.PEM_encode();
      
      
      std::ifstream message("checks/messages/ec_for_flex_mes");
      if(!message)
         {
         std::cout << "Couldn't read the message file." << std::endl;
         return 1;
         }
 
      std::string outfile = "checks/messages/ec_for_flex_mes.sig";
      std::ofstream sigfile(outfile.c_str());
      if(!sigfile)
         {
         std::cout << "Couldn't write the signature to "
                   << outfile << std::endl;
         return 1;
         }
 
      std::auto_ptr<Botan::PK_Signer> dsa_sig = get_pk_signer(key, "EMSA1(SHA-224)");
	  
      std::tr1::shared_ptr<Botan::PK_Signer> sp_dsa_sig(dsa_sig);
	        
	  Pipe pipe(create_shared_ptr<PK_Signer_Filter>(sp_dsa_sig), create_shared_ptr<Base64_Encoder>());	  
 
      pipe.start_msg();
      message >> pipe;
      pipe.end_msg();
 
      sigfile << pipe.read_all_as_string() << std::endl;
      
      
      std::auto_ptr<X509_PublicKey> pubkey = cert.subject_public_key();
  	  bool ver_ec = cert.check_signature(*pubkey);
      cout << ver_ec << endl;
   }
   catch(std::exception& e)
      {
      std::cout << "Exception: " << e.what() << std::endl;
      return 1;
      }

   return 0;
   }
