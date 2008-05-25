#include <botan/x509self.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/botan.h>
#include <botan/ec.h>
#include "common.h"
#include <iostream>
#include <fstream>


using namespace Botan;
 
int main()
   {
 
   try {
 
 	
      LibraryInitializer init;
//      EC_Domain_Params dom_pars = global_config().get_ec_dompar("1.3.132.0.8");


	BigInt bi_p_secp("2117607112719756483104013348936480976596328609518055062007450442679169492999007105354629105748524349829824407773719892437896937279095106809");
	BigInt bi_a_secp("0xa377dede6b523333d36c78e9b0eaa3bf48ce93041f6d4fc34014d08f6833807498deedd4290101c5866e8dfb589485d13357b9e78c2d7fbe9fe");
	BigInt bi_b_secp("0xa9acf8c8ba617777e248509bcb4717d4db346202bf9e352cd5633731dd92a51b72a4dc3b3d17c823fcc8fbda4da08f25dea89046087342595a7");
	BigInt bi_order_g("0xb6172c9d588000000000000000000000000000000000000000000476c879048e5d85ea728ed2ea1c1db92c4e4f9652364fdcdba7755fa6c362f");
	string G_secp_comp = "04081523d03d4f12cd02879dea4bf6a4f3a7df26ed888f10c5b2235a1274c386a2f218300dee6ed217841164533bcdc903f07a096f9fbf4ee95bac098a111f296f5830fe5c35b3e344d5df3a2256985f64fbe6d0edcc4c61d18bef681dd399df3d0194c5a4315e012e0245ecea56365baa9e8be1f7";
	string oid = "1.3.6.1.4.1.8301.3.1.2.9.0.33";
	
	::Botan::SecureVector<byte> sv_G_secp_comp = decode_hex(G_secp_comp);
	CurveGFp curve ( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );
	PointGFp p_G = OS2ECP ( sv_G_secp_comp, curve );
	p_G.check_invariants();
 	  EC_Domain_Params dom_pars(curve, p_G, bi_order_g, BigInt(1)); 

      ECDSA_PrivateKey key(dom_pars);
   	  std::ofstream priv_key("checks/testdata/nodompar_private.pkcs8.pem");
 	  priv_key << PKCS8::PEM_encode(key);

	
	
   }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }
   return 0;
}
