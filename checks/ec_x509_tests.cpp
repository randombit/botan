#include <iostream>
#include <fstream>

#include <botan/ec.h>
#include <botan/x509self.h>
#include <botan/look_pk.h>

#include <botan/math/ec/point_gfp.h>
#include <botan/math/ec/curve_gfp.h>
#include <botan/math/gf/gfp_element.h>
#include <botan/enums.h>
using namespace Botan::math::gf;

BOOST_AUTO_TEST_CASE(test_X509_req)
{
//    cout << "test_X509_req started..." << endl;
    for(int i = 0; i< 2; i++)
    {
		cout << "." << flush;
        try
        {
            Botan::LibraryInitializer init;

            //Botan::EC_Domain_Params dom_pars = global_config().get_ec_dompar("1.3.132.0.8");
            Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.36.3.3.2.8.1.1.11"));
            //Botan::EC_Domain_Params dom_pars = global_config().get_ec_dompar("1.2.840.10045.3.1.1");
            //Botan::EC_Domain_Params dom_pars = global_config().get_ec_dompar("1.3.36.3.3.2.8.1.1.3");
            Botan::ECDSA_PrivateKey priv_key(dom_pars);
            string keyfile_name;
            string reqfile_name;
            if(i == 0)
            {
                reqfile_name = "checks/temp/x509_req_test_expl.pem";
                keyfile_name = "checks/temp/x509_test_privkey_expl_pw123456.pem";
                priv_key.set_parameter_encoding(Botan::ENC_EXPLICIT);
            }
            else if( i== 1)
            {
                reqfile_name = "checks/temp/x509_req_test_oid.pem";
                keyfile_name = "checks/temp/x509_test_privkey_oid_pw123456.pem";
                priv_key.set_parameter_encoding(Botan::ENC_OID);
            }
            /*else if(i==2) // not supported yet
            {
            reqfile_name = "checks/temp/x509_req_test_implCa.pem";
            keyfile_name = "checks/temp/x509_test_privkey_implCa_pw123456.pem";
            priv_key.set_parameter_encoding(Botan::EC_PublicKey::ENC_IMPLICITCA);
            }*/
            else
            {
                assert(false);
            }
            ofstream key_file(keyfile_name.c_str());
            key_file << Botan::PKCS8::PEM_encode(priv_key, "123456");


            Botan::X509_Cert_Options opts;

            opts.common_name = "test_zert";
            opts.country = "DE";
            opts.organization = "FlexSecure";
            opts.email = "test@test.de";

            // Some hard-coded options, just to give you an idea of what's there
            opts.challenge = "a fixed challenge passphrase";
            opts.locality = "Baltimore";
            opts.state = "MD";
            opts.org_unit = "Testing";
            opts.add_ex_constraint("PKIX.ClientAuth");
            opts.add_ex_constraint("PKIX.IPsecUser");
            opts.add_ex_constraint("PKIX.EmailProtection");

            Botan::PKCS10_Request req = Botan::X509::create_cert_req(opts, priv_key);

            std::ofstream req_file(reqfile_name.c_str());
            req_file << req.PEM_encode();
        }
        catch(exception& e)
        {
            string message = "Exception in test_eckaeg_store: ";
            message.append(e.what());
            BOOST_CHECK_MESSAGE(false, message);
        }
    }
//    cout << "test_X509_req finished" << endl;
}

BOOST_AUTO_TEST_CASE(test_X509_selfsign)
{
//    cout << "test_X509_selfsign started..." << endl;
    Botan::LibraryInitializer init;
    for(int i =0; i<2; i++) // NOTE: implicitByCA not yet supported
    {
		cout << "." << flush;
        try
        {
            //Botan::EC_Domain_Params dom_pars = global_config().get_ec_dompar("1.3.132.0.8");
            Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.36.3.3.2.8.1.1.11"));
            //Botan::ECDSA_PrivateKey key = ECDSA_PrivateKey(dom_pars);
            Botan::ECDSA_PrivateKey key(dom_pars);
            //Botan::RSA_PrivateKey key(1024);
            //Botan::DSA_PrivateKey key(DL_Group("dsa/jce/1024"));
            ofstream priv_key("checks/temp/private.pem");
            priv_key << Botan::PKCS8::PEM_encode(key);
            Botan::X509_Cert_Options opts;
            opts.common_name = "InSiTo Test CA";
            opts.country = "DE";
            opts.organization = "FlexSecure";
            opts.email = "test@test.de";
            opts.CA_key();
            string certFileName;

            if(i == 0)
            {
                key.set_parameter_encoding(Botan::ENC_EXPLICIT);
                certFileName = "checks/temp/insito_expl_ec.pem";
            }
            else if(i == 1)
            {
                key.set_parameter_encoding(Botan::ENC_OID);
                certFileName = "checks/temp/insito_oid_ec.pem";
            }
            else if(i == 2)
            {
                key.set_parameter_encoding(Botan::ENC_IMPLICITCA);
                certFileName = "checks/temp/insito_implCa_ec.pem";
            }
            else
            {
                assert(false);
            }

            Botan::X509_Certificate cert = Botan::X509::create_self_signed_cert(opts, key);
            ofstream cert_file(certFileName.c_str());
            cert_file << cert.PEM_encode();
            ifstream message("checks/messages/ec_for_flex_mes");
            if(!message)
            {
                BOOST_CHECK_MESSAGE(false, "Couldn't read the message file: checks/messages/ec_for_flex_mes");
                return;
            }
            string outfile = "checks/temp/ec_for_flex_mes.sig";
            ofstream sigfile(outfile.c_str());
            if(!sigfile)
            {
                BOOST_CHECK_MESSAGE(false, "Couldn't write the signature to " << outfile);
                return;
            }
            auto_ptr<Botan::PK_Signer> dsa_sig = Botan::get_pk_signer(key, "EMSA1_BSI(SHA-1)");
            tr1::shared_ptr<Botan::PK_Signer> sp_dsa_sig(dsa_sig);
            Botan::Pipe pipe(Botan::create_shared_ptr<Botan::PK_Signer_Filter>(sp_dsa_sig),
                Botan::create_shared_ptr<Botan::Base64_Encoder>());
            pipe.start_msg();
            message >> pipe;
            pipe.end_msg();
            sigfile << pipe.read_all_as_string() << std::endl;
            auto_ptr<Botan::X509_PublicKey> pubkey = cert.subject_public_key();
            bool ver_ec = cert.check_signature(*pubkey);
            BOOST_CHECK_MESSAGE(ver_ec, "couldn't verify signature of self_signed certificate");
        }
        catch(std::exception& e)
        {
            string message = "Exception in test_X509_selfsign: ";
            message.append(e.what());
            BOOST_CHECK_MESSAGE(false, message);
        }
    }
//    cout << "test_X509_selfsign finished" << endl;
}
