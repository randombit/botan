/******************************************************
* ECDSA tests                                         *
*                                                     *
* (C) 2007 Falko Strenzke                             *
*          hartl@flexsecure.de                        *
******************************************************/

#include <botan/botan.h>
#include <botan/oids.h>
#include <botan/ecdsa.h>
#include <botan/rsa.h>
#include <botan/x509cert.h>
#include <botan/freestore.h>
#include <botan/look_pk.h>
#include <botan/bigint.h>
#include <botan/numthry.h>
#include <botan/gfp_element.h>
#include <botan/gfp_modulus.h>
#include <botan/curve_gfp.h>
#include <botan/ec_dompar.h>
#include <botan/pipe.h>

#include <iostream>
#include <fstream>

using namespace Botan;
using namespace std;

#define BOOST_AUTO_TEST_CASE(name) void name()
#define BOOST_CHECK_MESSAGE(expr, print) if(!(expr)) std::cout << print << "\n";
#define BOOST_CHECK(expr) if(!(expr)) std::cout << #expr << "\n";

namespace {

string to_hex(const Botan::SecureVector<Botan::byte>& bin)
   {
   Botan::Pipe pipe(new Hex_Encoder);
   pipe.process_msg(bin);
   if (pipe.remaining())
      return pipe.read_all_as_string();
   else
      return "(none)";
   }

SecureVector<byte> decode_hex(const std::string& in)
   {
   SecureVector<byte> result;

   try {
      Botan::Pipe pipe(new Botan::Hex_Decoder);
      pipe.process_msg(in);
      result = pipe.read_all();
   }
   catch(std::exception& e)
      {
      result.destroy();
      }
   return result;
   }

}

/**

 * Tests whether the the signing routine will work correctly in case the integer e
 * that is constructed from the message (thus the hash value) is larger than n, the order of the base point.
 * Tests the signing function of the pk signer object
 */

BOOST_AUTO_TEST_CASE( test_hash_larger_than_n)
{
  cout << "." << flush;

  std::auto_ptr<RandomNumberGenerator> rng(
     RandomNumberGenerator::make_rng());

  //EC_Domain_Params dom_pars = global_config().get_ec_dompar("1.3.132.0.8");
  Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.132.0.8"));
  // n:
  // 0x0100000000000000000001f4c8f927aed3ca752257 // 21 bytes
  // -> shouldn´t work with SHA224 which outputs 23 bytes
  Botan::ECDSA_PrivateKey priv_key(*rng, dom_pars);
  Botan::SecureVector<Botan::byte> message;
  for (unsigned j= 0; j<20; j++)
    {
      message.append(j);
    }

  for (int i = 0; i<3; i++)
  {
      //cout << "i = " << i << endl;
      std::string format;
      if(i==1)
      {
          format = "EMSA1_BSI(SHA-224)";
      }
      else
      {
             format = "EMSA1_BSI(SHA-1)";
      }
      auto_ptr<Botan::PK_Signer> pk_signer(get_pk_signer(priv_key, format));
      Botan::SecureVector<Botan::byte> signature;
  bool sig_exc = false;
  try
  {
  signature = pk_signer->sign_message(message, *rng);
  }
  catch(Botan::Encoding_Error e)
  {
   sig_exc = true;
  }
  if(i==1)
  {
    BOOST_CHECK(sig_exc);
  }
  if(i==0)
  {
   BOOST_CHECK(!sig_exc);
  }


  if(i==0) // makes no sense to check for sha224
    {
    auto_ptr<Botan::PK_Verifier> pk_verifier(get_pk_verifier(priv_key, format));
    bool ver = pk_verifier->verify_message(message, signature);
    BOOST_CHECK(ver);
    }

  } // for

  // now check that verification alone fails

 // sign it with the normal EMSA1
  auto_ptr<Botan::PK_Signer> pk_signer(get_pk_signer(priv_key, "EMSA1(SHA-224)"));
  Botan::SecureVector<Botan::byte> signature = pk_signer->sign_message(message, *rng);

  auto_ptr<Botan::PK_Verifier> pk_verifier(get_pk_verifier(priv_key, "EMSA1_BSI(SHA-224)"));


  // verify against EMSA1_BSI
  // we make sure it doesn´t fail because of the invalid signature,
  // but because of the Encoding_Error
  bool ver_exc = false;
  try
  {
    pk_verifier->verify_message(message, signature);
  }
  catch(Botan::Encoding_Error e)
  {
      ver_exc = true;
  }
  BOOST_CHECK(ver_exc);


}


/**
* Tests whether the the signing routine will work correctly in case the integer e
* that is constructed from the message is larger than n, the order of the base point
*/
BOOST_AUTO_TEST_CASE( test_message_larger_than_n)
{
  cout << "." << flush;

  std::auto_ptr<RandomNumberGenerator> rng(RandomNumberGenerator::make_rng());

  //Botan::EC_Domain_Params dom_pars = global_config().get_ec_dompar("1.3.132.0.8");
  Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.132.0.8"));
  //Botan::EC_Domain_Params dom_pars = global_config().get_ec_dompar("1.2.840.10045.3.1.1");
  //Botan::EC_Domain_Params dom_pars = global_config().get_ec_dompar("1.3.36.3.3.2.8.1.1.3");
  Botan::ECDSA_PrivateKey priv_key(*rng, dom_pars);
  string str_message = ("12345678901234567890abcdef1212345678901234567890abcdef1212345678901234567890abcdef12");
  Botan::SecureVector<Botan::byte> sv_message = decode_hex(str_message);
  bool thrn = false;
  Botan::SecureVector<Botan::byte> signature;
  try
    {
    signature = priv_key.sign(sv_message.begin(), sv_message.size(), *rng);
    }
  catch (Botan::Invalid_Argument e)
    {
      thrn = true;
    }
  //cout << "signature = " << hex_encode(signature.begin(), signature.size()) << "\n";
  bool ver_success = priv_key.verify(sv_message.begin(), sv_message.size(), signature.begin(), signature.size());
  BOOST_CHECK_MESSAGE(ver_success, "generated signature could not be verified positively");
  //BOOST_CHECK_MESSAGE(thrn, "no exception was thrown although message to sign was too long");
}

BOOST_AUTO_TEST_CASE( test_decode_ecdsa_X509)
{
  cout << "." << flush;

  Botan::X509_Certificate cert("checks/testdata/CSCA.CSCA.csca-germany.1.crt");
  BOOST_CHECK_MESSAGE(Botan::OIDS::lookup(cert.signature_algorithm().oid) == "ECDSA/EMSA1_BSI(SHA-224)", "error reading signature algorithm from x509 ecdsa certificate");
  BOOST_CHECK_MESSAGE(to_hex(cert.serial_number()) == "01", "error reading serial from x509 ecdsa certificate");
  BOOST_CHECK_MESSAGE(to_hex(cert.authority_key_id()) == "0096452DE588F966C4CCDF161DD1F3F5341B71E7", "error reading authority key id from x509 ecdsa certificate");
  BOOST_CHECK_MESSAGE(to_hex(cert.subject_key_id()) == "0096452DE588F966C4CCDF161DD1F3F5341B71E7", "error reading Subject key id from x509 ecdsa certificate");

  auto_ptr<Botan::X509_PublicKey> pubkey(cert.subject_public_key());
  bool ver_ec = cert.check_signature(*pubkey);
  BOOST_CHECK_MESSAGE(ver_ec, "could not positively verify correct selfsigned x509-ecdsa certificate");
}

BOOST_AUTO_TEST_CASE( test_decode_ver_link_SHA256)
{
  cout << "." << flush;

  Botan::X509_Certificate root_cert("checks/testdata/root2_SHA256.cer");
  Botan::X509_Certificate link_cert("checks/testdata/link_SHA256.cer");

  auto_ptr<Botan::X509_PublicKey> pubkey(root_cert.subject_public_key());
  bool ver_ec = link_cert.check_signature(*pubkey);
  BOOST_CHECK_MESSAGE(ver_ec, "could not positively verifiy correct SHA256 link x509-ecdsa certificate");

}
BOOST_AUTO_TEST_CASE( test_decode_ver_link_SHA1)
{
  cout << "." << flush;

  Botan::X509_Certificate root_cert("checks/testdata/root_SHA1.163.crt");
  Botan::X509_Certificate link_cert("checks/testdata/link_SHA1.166.crt");

  auto_ptr<Botan::X509_PublicKey> pubkey(root_cert.subject_public_key());
  bool ver_ec = link_cert.check_signature(*pubkey);
  BOOST_CHECK_MESSAGE(ver_ec, "could not positively verifiy correct SHA1 link x509-ecdsa certificate");
}

BOOST_AUTO_TEST_CASE( test_sign_then_ver)
{
  cout << "." << flush;

  std::auto_ptr<RandomNumberGenerator> rng(RandomNumberGenerator::make_rng());

  string g_secp("024a96b5688ef573284664698968c38bb913cbfc82");
  Botan::SecureVector<Botan::byte> sv_g_secp = decode_hex(g_secp);
  BigInt bi_p_secp("0xffffffffffffffffffffffffffffffff7fffffff");
  BigInt bi_a_secp("0xffffffffffffffffffffffffffffffff7ffffffc");
  BigInt bi_b_secp("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
  BigInt order = BigInt("0x0100000000000000000001f4c8f927aed3ca752257");
  CurveGFp curve(GFpElement(bi_p_secp,bi_a_secp), GFpElement(bi_p_secp, bi_b_secp), bi_p_secp);
  BigInt cofactor = BigInt(1);
  PointGFp p_G = OS2ECP ( sv_g_secp, curve );

  Botan::EC_Domain_Params dom_pars = Botan::EC_Domain_Params(curve, p_G, order, cofactor);
  Botan::ECDSA_PrivateKey my_priv_key(*rng, dom_pars);

  string str_message = ("12345678901234567890abcdef12");
  Botan::SecureVector<Botan::byte> sv_message = decode_hex(str_message);
  Botan::SecureVector<Botan::byte> signature = my_priv_key.sign(sv_message.begin(), sv_message.size(), *rng);
  //cout << "signature = " << hex_encode(signature.begin(), signature.size()) << "\n";
  bool ver_success = my_priv_key.verify(sv_message.begin(), sv_message.size(), signature.begin(), signature.size());
  BOOST_CHECK_MESSAGE(ver_success, "generated signature could not be verified positively");
  signature[signature.size()-1] += 0x01;
  bool ver_must_fail = my_priv_key.verify(sv_message.begin(), sv_message.size(), signature.begin(), signature.size());
  BOOST_CHECK_MESSAGE(!ver_must_fail, "corrupted signature could be verified positively");
}

BOOST_AUTO_TEST_CASE(test_ec_sign)
{
  cout << "." << flush;

#if 0
  try
    {
      ifstream message("checks/messages/ec_test_mes1");
      if (!message)
        {
          BOOST_CHECK_MESSAGE(false, "Couldn't read the message file.");
          return;
        }

      string outfile = "checks/temp/ec_test_mes1.sig";
      ofstream sigfile(outfile.c_str());
      if (!sigfile)
        {
          BOOST_CHECK_MESSAGE(false, "Couldn't write the signature to " << outfile);
          return;
        }

      std::auto_ptr<RandomNumberGenerator> rng(RandomNumberGenerator::make_rng());

      //Botan::EC_Domain_Params dom_pars = global_config().get_ec_dompar("1.3.132.0.8");
      Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.132.0.8"));

      Botan::ECDSA_PrivateKey priv_key(*rng, dom_pars);
      auto_ptr<Botan::PK_Signer> dsa_sig(Botan::get_pk_signer(priv_key, "EMSA1(SHA-224)"));

      tr1::shared_ptr<Botan::PK_Signer> sp_dsa_sig(dsa_sig);

      Botan::Pipe pipe(new Botan::Base64_Encoder);
      pipe.process_msg(sp_dsa_sign->signature(*rng));

      pipe.start_msg();
      message >> pipe;
      pipe.end_msg();

      sigfile << pipe.read_all_as_string() << endl;

      ofstream os_priv_key("checks/temp/matching_key.pkcs8.pem");

      os_priv_key << Botan::PKCS8::PEM_encode(priv_key);
      //BOOST_CHECK(true);
    }

  catch (exception& e)
    {
      BOOST_CHECK_MESSAGE(false, "something went wrong while signing...");
    }
#endif
}


BOOST_AUTO_TEST_CASE( test_create_pkcs8)
{
  cout << "." << flush;
  try
    {
    std::auto_ptr<RandomNumberGenerator> rng(RandomNumberGenerator::make_rng());

      Botan::RSA_PrivateKey rsa_key(*rng, 1024);
      //RSA_PrivateKey rsa_key2(1024);
      //cout << "\nequal: " <<  (rsa_key == rsa_key2) << "\n";
      //DSA_PrivateKey key(DL_Group("dsa/jce/1024"));

      ofstream rsa_priv_key("checks/temp/rsa_private.pkcs8.pem");
      rsa_priv_key << Botan::PKCS8::PEM_encode(rsa_key);

      //Botan::EC_Domain_Params dom_pars = global_config().get_ec_dompar("1.3.132.0.8");
      Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.132.0.8"));
      Botan::ECDSA_PrivateKey key(*rng, dom_pars);
      ofstream priv_key("checks/temp/wo_dompar_private.pkcs8.pem");
      priv_key << Botan::PKCS8::PEM_encode(key);
      //BOOST_CHECK(true);
    }

  catch (exception& e)
    {
      BOOST_CHECK_MESSAGE(false, "something went wrong while writing key-file");
    }
}

BOOST_AUTO_TEST_CASE( test_create_and_verify)
{
    std::auto_ptr<RandomNumberGenerator> rng(RandomNumberGenerator::make_rng());

  {
	  cout << "." << flush;
//    cout << "create_and_verify started" << endl;


    //Botan::EC_Domain_Params dom_pars = global_config().get_ec_dompar("1.3.132.0.8");
    Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.132.0.8"));
    Botan::ECDSA_PrivateKey key(*rng, dom_pars);
    ofstream priv_key("checks/temp/dompar_private.pkcs8.pem");
    priv_key << Botan::PKCS8::PEM_encode(key);

    auto_ptr<Botan::PKCS8_PrivateKey> loaded_key(Botan::PKCS8::load_key("checks/temp/wo_dompar_private.pkcs8.pem", *rng));
    Botan::ECDSA_PrivateKey* loaded_ec_key = dynamic_cast<Botan::ECDSA_PrivateKey*>(loaded_key.get());
    BOOST_CHECK_MESSAGE(loaded_ec_key, "the loaded key could not be converted into an ECDSA_PrivateKey");

    auto_ptr<Botan::PKCS8_PrivateKey> loaded_key_1(Botan::PKCS8::load_key("checks/temp/rsa_private.pkcs8.pem", *rng));
    Botan::ECDSA_PrivateKey* loaded_rsa_key = dynamic_cast<Botan::ECDSA_PrivateKey*>(loaded_key_1.get());
    BOOST_CHECK_MESSAGE(!loaded_rsa_key, "the loaded key is ECDSA_PrivateKey -> shouldn't be, is a RSA-Key");
  }

  {
    //calc a curve which is not in the registry

    // init the lib

    // 	string p_secp = "2117607112719756483104013348936480976596328609518055062007450442679169492999007105354629105748524349829824407773719892437896937279095106809";
    string a_secp = "0a377dede6b523333d36c78e9b0eaa3bf48ce93041f6d4fc34014d08f6833807498deedd4290101c5866e8dfb589485d13357b9e78c2d7fbe9fe";
    string b_secp = "0a9acf8c8ba617777e248509bcb4717d4db346202bf9e352cd5633731dd92a51b72a4dc3b3d17c823fcc8fbda4da08f25dea89046087342595a7";
    string G_secp_comp = "04081523d03d4f12cd02879dea4bf6a4f3a7df26ed888f10c5b2235a1274c386a2f218300dee6ed217841164533bcdc903f07a096f9fbf4ee95bac098a111f296f5830fe5c35b3e344d5df3a2256985f64fbe6d0edcc4c61d18bef681dd399df3d0194c5a4315e012e0245ecea56365baa9e8be1f7";
    string order_g = "0e1a16196e6000000000bc7f1618d867b15bb86474418f";

    //	::Botan::SecureVector<byte> sv_p_secp = decode_hex ( p_secp );
    Botan::SecureVector<Botan::byte> sv_a_secp = decode_hex ( a_secp );
    Botan::SecureVector<Botan::byte> sv_b_secp = decode_hex ( b_secp );
    Botan::SecureVector<Botan::byte> sv_G_secp_comp = decode_hex ( G_secp_comp );
    Botan::SecureVector<Botan::byte> sv_order_g = decode_hex ( order_g );

    //	BigInt bi_p_secp = BigInt::decode ( sv_p_secp.begin(), sv_p_secp.size() );
    BigInt bi_p_secp("2117607112719756483104013348936480976596328609518055062007450442679169492999007105354629105748524349829824407773719892437896937279095106809");
    BigInt bi_a_secp = BigInt::decode ( sv_a_secp.begin(), sv_a_secp.size() );
    BigInt bi_b_secp = BigInt::decode ( sv_b_secp.begin(), sv_b_secp.size() );
    BigInt bi_order_g = BigInt::decode ( sv_order_g.begin(), sv_order_g.size() );
    CurveGFp curve ( GFpElement ( bi_p_secp,bi_a_secp ), GFpElement ( bi_p_secp, bi_b_secp ), bi_p_secp );
    PointGFp p_G = OS2ECP ( sv_G_secp_comp, curve );
    {
      Botan::EC_Domain_Params dom_params(curve, p_G, bi_order_g, BigInt(1));
      p_G.check_invariants();
      Botan::ECDSA_PrivateKey key(*rng, dom_params);
      ofstream priv_key("checks/temp/ec_oid_not_in_reg_private.pkcs8.pem");
      priv_key << Botan::PKCS8::PEM_encode(key);
    }

    auto_ptr<Botan::PKCS8_PrivateKey> loaded_key(Botan::PKCS8::load_key("checks/temp/ec_oid_not_in_reg_private.pkcs8.pem", *rng));
    Botan::ECDSA_PrivateKey* loaded_ec_key = dynamic_cast<Botan::ECDSA_PrivateKey*>(loaded_key.get());
    BOOST_CHECK_MESSAGE(loaded_ec_key, "the loaded key could not be converted into an ECDSA_PrivateKey");
  }

//  cout << "create_and_verify finished" << endl;
}

BOOST_AUTO_TEST_CASE( test_curve_registry)
{
  bool skip_test = false;
  //cout << "start test_curve_registry " << endl;

  if (skip_test)
    {
      //cout << "test_curve_registry disabled" << endl;
      return;
    }

  // setting up oid's
  vector<string> oids;
  oids.push_back("1.3.132.0.8");
  oids.push_back("1.2.840.10045.3.1.1");
  oids.push_back("1.2.840.10045.3.1.2");
  oids.push_back("1.2.840.10045.3.1.3");
  oids.push_back("1.2.840.10045.3.1.4");
  oids.push_back("1.2.840.10045.3.1.5");
  oids.push_back("1.2.840.10045.3.1.6");
  oids.push_back("1.2.840.10045.3.1.7");
  oids.push_back("1.3.132.0.6");
  oids.push_back("1.3.132.0.7");
  oids.push_back("1.3.132.0.28");
  oids.push_back("1.3.132.0.29");
  oids.push_back("1.3.132.0.9");
  oids.push_back("1.3.132.0.30");
  oids.push_back("1.3.132.0.31");
  oids.push_back("1.3.132.0.32");
  oids.push_back("1.3.132.0.33");
  oids.push_back("1.3.132.0.10");
  oids.push_back("1.3.132.0.34");
  oids.push_back("1.3.132.0.35");
  oids.push_back("1.3.6.1.4.1.8301.3.1.2.9.0.38");
  oids.push_back("1.3.36.3.3.2.8.1.1.1");
  oids.push_back("1.3.36.3.3.2.8.1.1.3");
  oids.push_back("1.3.36.3.3.2.8.1.1.5");
  oids.push_back("1.3.36.3.3.2.8.1.1.7");
  oids.push_back("1.3.36.3.3.2.8.1.1.9");
  oids.push_back("1.3.36.3.3.2.8.1.1.11");
  oids.push_back("1.3.36.3.3.2.8.1.1.13");

  std::auto_ptr<RandomNumberGenerator> rng(RandomNumberGenerator::make_rng());

  unsigned int i;
  for (i = 0; i < oids.size(); i++)
    {
      cout << "." << flush;
      //cout << "testing curve " << i+1 << "/" << oids.size() << ": " << oids[i] << endl;
      //EC_Domain_Params dom_pars = global_config().get_ec_dompar(oids[i]);
      Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid(oids[i]));
      dom_pars.get_base_point().check_invariants();
      Botan::ECDSA_PrivateKey key(*rng, dom_pars);

      string str_message = ("12345678901234567890abcdef12");
      Botan::SecureVector<Botan::byte> sv_message = decode_hex(str_message);
      Botan::SecureVector<Botan::byte> signature = key.sign(sv_message.begin(), sv_message.size(), *rng);
      bool ver_success = key.verify(sv_message.begin(), sv_message.size(), signature.begin(), signature.size());
      BOOST_CHECK_MESSAGE(ver_success, "generated signature could not be verified positively");
    }
//  cout << "test_curve_registry finished" << endl;
}

BOOST_AUTO_TEST_CASE( test_read_pkcs8)
{
  cout << "." << flush;
  try
    {
    std::auto_ptr<RandomNumberGenerator> rng(RandomNumberGenerator::make_rng());

    auto_ptr<Botan::PKCS8_PrivateKey> loaded_key(Botan::PKCS8::load_key("checks/temp/wo_dompar_private.pkcs8.pem", *rng));
      Botan::ECDSA_PrivateKey* loaded_ec_key = dynamic_cast<Botan::ECDSA_PrivateKey*>(loaded_key.get());
      BOOST_CHECK_MESSAGE(loaded_ec_key, "the loaded key could not be converted into an ECDSA_PrivateKey");

      string str_message = ("12345678901234567890abcdef12");
      Botan::SecureVector<Botan::byte> sv_message = decode_hex(str_message);
      Botan::SecureVector<Botan::byte> signature = loaded_ec_key->sign(sv_message.begin(), sv_message.size(), *rng);
      //cout << "signature = " << hex_encode(signature.begin(), signature.size()) << "\n";
      bool ver_success = loaded_ec_key->verify(sv_message.begin(), sv_message.size(), signature.begin(), signature.size());
      BOOST_CHECK_MESSAGE(ver_success, "generated signature could not be verified positively");

      auto_ptr<Botan::PKCS8_PrivateKey> loaded_key_nodp(Botan::PKCS8::load_key("checks/testdata/nodompar_private.pkcs8.pem", *rng));
      // anew in each test with unregistered domain-parameters
      Botan::ECDSA_PrivateKey* loaded_ec_key_nodp = dynamic_cast<Botan::ECDSA_PrivateKey*>(loaded_key_nodp.get());
      BOOST_CHECK_MESSAGE(loaded_ec_key_nodp, "the loaded key could not be converted into an ECDSA_PrivateKey");

      Botan::SecureVector<Botan::byte> signature_nodp = loaded_ec_key_nodp->sign(sv_message.begin(), sv_message.size(), *rng);
      //cout << "signature = " << hex_encode(signature.begin(), signature.size()) << "\n";
      bool ver_success_nodp = loaded_ec_key_nodp->verify(sv_message.begin(), sv_message.size(), signature_nodp.begin(), signature_nodp.size());
      BOOST_CHECK_MESSAGE(ver_success_nodp, "generated signature could not be verified positively (no_dom)");
      try
        {
        auto_ptr<Botan::PKCS8_PrivateKey> loaded_key_withdp(Botan::PKCS8::load_key("checks/testdata/withdompar_private.pkcs8.pem", *rng));
          BOOST_CHECK_MESSAGE(false, "could load key but unknown OID is set");
        }
      catch (exception& e)
        {
          BOOST_CHECK(true);
        }
    }
  catch (exception& e)
    {
      BOOST_CHECK_MESSAGE(false, "Exception in test_read_pkcs8 message: " << e.what());
    }
}

/**
* The following test tests the copy ctors and and copy-assignment operators
*/
BOOST_AUTO_TEST_CASE( test_cp_and_as_ctors )
{
  cout << "." << flush;

  std::auto_ptr<RandomNumberGenerator> rng(RandomNumberGenerator::make_rng());

  auto_ptr<Botan::PKCS8_PrivateKey> loaded_key(Botan::PKCS8::load_key("checks/temp/wo_dompar_private.pkcs8.pem", *rng));
  Botan::ECDSA_PrivateKey* loaded_ec_key = dynamic_cast<Botan::ECDSA_PrivateKey*>(loaded_key.get());
  BOOST_CHECK_MESSAGE(loaded_ec_key, "the loaded key could not be converted into an ECDSA_PrivateKey");
  string str_message = ("12345678901234567890abcdef12");
  Botan::SecureVector<Botan::byte> sv_message = decode_hex(str_message);
  Botan::SecureVector<Botan::byte> signature_1 = loaded_ec_key->sign(sv_message.begin(), sv_message.size(), *rng);
  //cout << "signature = " << hex_encode(signature.begin(), signature.size()) << "\n";

  Botan::ECDSA_PrivateKey cp_priv_key(*loaded_ec_key); // priv-key, cp-ctor
  Botan::SecureVector<Botan::byte> signature_2 = cp_priv_key.sign(sv_message.begin(), sv_message.size(), *rng);

  Botan::ECDSA_PrivateKey as_priv_key = *loaded_ec_key;  //priv-key, as-op
  Botan::SecureVector<Botan::byte> signature_3 = as_priv_key.sign(sv_message.begin(), sv_message.size(), *rng);

  Botan::ECDSA_PublicKey pk_1 = cp_priv_key; // pub-key, as-op
  Botan::ECDSA_PublicKey pk_2(pk_1); // pub-key, cp-ctor
  Botan::ECDSA_PublicKey pk_3;
  pk_3 = pk_2; // pub-key, as-op

  bool ver_success_1 = pk_1.verify(sv_message.begin(), sv_message.size(), signature_1.begin(), signature_1.size());

  bool ver_success_2 = pk_2.verify(sv_message.begin(), sv_message.size(), signature_2.begin(), signature_2.size());

  bool ver_success_3 = pk_3.verify(sv_message.begin(), sv_message.size(), signature_3.begin(), signature_3.size());

  BOOST_CHECK_MESSAGE((ver_success_1 && ver_success_2 && ver_success_3), "different results for copied keys");
}

/**
* The following test tests whether ECDSA keys exhibit correct behaviour when it is
* attempted to use them in an uninitialized state
*/
BOOST_AUTO_TEST_CASE( test_non_init_ecdsa_keys )
{
  cout << "." << flush;

  std::auto_ptr<RandomNumberGenerator> rng(RandomNumberGenerator::make_rng());

  auto_ptr<Botan::PKCS8_PrivateKey> loaded_key(Botan::PKCS8::load_key("checks/temp/wo_dompar_private.pkcs8.pem", *rng));
  //Botan::ECDSA_PrivateKey* loaded_ec_key = dynamic_cast<Botan::ECDSA_PrivateKey*>(loaded_key.get());
  //BOOST_CHECK_MESSAGE(loaded_ec_key, "the loaded key could not be converted into an ECDSA_PrivateKey");
  string str_message = ("12345678901234567890abcdef12");
  Botan::ECDSA_PrivateKey empty_priv;
  Botan::ECDSA_PublicKey empty_pub;
  Botan::SecureVector<Botan::byte> sv_message = decode_hex(str_message);
  bool exc1 = false;
  try
    {
    Botan::SecureVector<Botan::byte> signature_1 = empty_priv.sign(sv_message.begin(), sv_message.size(), *rng);
    }
  catch (Botan::Exception e)
    {
      exc1 = true;
    }
  BOOST_CHECK_MESSAGE(exc1, "there was no exception thrown when attempting to use an uninitialized ECDSA key");

  bool exc2 = false;
  try
    {
      empty_pub.verify(sv_message.begin(), sv_message.size(), sv_message.begin(), sv_message.size());
    }
  catch (Botan::Exception e)
    {
      exc2 = true;
    }
  BOOST_CHECK_MESSAGE(exc2, "there was no exception thrown when attempting to use an uninitialized ECDSA key");
}

int main()
   {
    Botan::InitializerOptions init_options("");
    Botan::LibraryInitializer init(init_options);

   test_hash_larger_than_n();
   test_message_larger_than_n();
   test_decode_ecdsa_X509();
   test_decode_ver_link_SHA256();
   test_decode_ver_link_SHA1();
   test_sign_then_ver();
   test_ec_sign();
   test_create_pkcs8();
   test_create_and_verify();
   test_curve_registry();
   test_read_pkcs8();
   test_cp_and_as_ctors();
   test_non_init_ecdsa_keys();
   }
