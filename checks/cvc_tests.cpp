/*
* CVC EAC1.1 tests
*
* (C) 2008 Falko Strenzke (strenzke@flexsecure.de)
*     2008 Jack Lloyd
*/

#include "validate.h"
#include <botan/build.h>

#if defined(BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES)

#include <iosfwd>
#include <iostream>
#include <iterator>
#include <algorithm>
#include <fstream>
#include <vector>
#include <memory>

#include <botan/ecdsa.h>
#include <botan/rsa.h>

#include <botan/x509cert.h>
#include <botan/x509self.h>
#include <botan/oids.h>
#include <botan/cvc_self.h>
#include <botan/cvc_cert.h>
#include <botan/cvc_ado.h>
#include <botan/time.h>

#define TEST_DATA_DIR "checks/ecc_testdata"

using namespace Botan;

#define CHECK_MESSAGE(expr, print) try { if(!(expr)) std::cout << print << "\n"; } catch(std::exception& e) { std::cout << __FUNCTION__ << ": " << e.what() << "\n"; }
#define CHECK(expr) try { if(!(expr)) std::cout << #expr << "\n"; } catch(std::exception& e) { std::cout << __FUNCTION__ << ": " << e.what() << "\n"; }

namespace {

// helper functions
void helper_write_file(EAC_Signed_Object const& to_write, std::string const& file_path)
   {
   SecureVector<byte> sv = to_write.BER_encode();
   std::ofstream cert_file(file_path.c_str(), std::ios::binary);
   cert_file.write((char*)&sv[0], sv.size());
   cert_file.close();
   }

bool helper_files_equal(std::string const& file_path1, std::string const& file_path2)
   {
   std::ifstream cert_1_in(file_path1.c_str());
   std::ifstream cert_2_in(file_path2.c_str());
   SecureVector<byte> sv1;
   SecureVector<byte> sv2;
   if (!cert_1_in || !cert_2_in)
      {
      return false;
      }
   while (!cert_1_in.eof())
      {
      char now;
      cert_1_in.read(&now, 1);
      sv1.push_back(now);
      }
   while (!cert_2_in.eof())
      {
      char now;
      cert_2_in.read(&now, 1);
      sv2.push_back(now);
      }
   if (sv1.size() == 0)
      {
      return false;
      }
   return sv1 == sv2;
   }

void test_enc_gen_selfsigned(RandomNumberGenerator& rng)
   {
   std::cout << '.' << std::flush;

   EAC1_1_CVC_Options opts;
   //opts.cpi = 0;
   opts.chr = ASN1_Chr("my_opt_chr"); // not used
   opts.car = ASN1_Car("my_opt_car");
   opts.cex = ASN1_Cex("2010 08 13");
   opts.ced = ASN1_Ced("2010 07 27");
   opts.holder_auth_templ = 0xC1;
   opts.hash_alg = "SHA-256";

   // creating a non sense selfsigned cert w/o dom pars
   EC_Group dom_pars(OID("1.3.36.3.3.2.8.1.1.11"));
   ECDSA_PrivateKey key(rng, dom_pars);
   key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
   EAC1_1_CVC cert = CVC_EAC::create_self_signed_cert(key, opts, rng);

   SecureVector<byte> der(cert.BER_encode());
   std::ofstream cert_file;
   cert_file.open(TEST_DATA_DIR "/my_cv_cert.ber", std::ios::binary);
   //cert_file << der; // this is bad !!!
   cert_file.write((char*)&der[0], der.size());
   cert_file.close();

   EAC1_1_CVC cert_in(TEST_DATA_DIR "/my_cv_cert.ber");
   CHECK(cert == cert_in);
   // encoding it again while it has no dp
   SecureVector<byte> der2(cert_in.BER_encode());
   std::ofstream cert_file2(TEST_DATA_DIR "/my_cv_cert2.ber", std::ios::binary);
   cert_file2.write((char*)&der2[0], der2.size());
   cert_file2.close();
   // read both and compare them
   std::ifstream cert_1_in(TEST_DATA_DIR "/my_cv_cert.ber");
   std::ifstream cert_2_in(TEST_DATA_DIR "/my_cv_cert2.ber");
   SecureVector<byte> sv1;
   SecureVector<byte> sv2;
   if (!cert_1_in || !cert_2_in)
      {
      CHECK_MESSAGE(false, "could not read certificate files");
      }
   while (!cert_1_in.eof())
      {
      char now;

      cert_1_in.read(&now, 1);
      sv1.push_back(now);
      }
   while (!cert_2_in.eof())
      {
      char now;
      cert_2_in.read(&now, 1);
      sv2.push_back(now);
      }
   CHECK(sv1.size() > 10);
   CHECK_MESSAGE(sv1 == sv2, "reencoded file of cert without domain parameters is different from original");

   //cout << "reading cert again\n";
   CHECK(cert_in.get_car().value() == "my_opt_car");
   CHECK(cert_in.get_chr().value() == "my_opt_car");
   CHECK(cert_in.get_ced().as_string() == "20100727");
   CHECK(cert_in.get_ced().readable_string() == "2010/07/27 ");

   bool ill_date_exc = false;
   try
      {
      ASN1_Ced("1999 01 01");
      }
   catch (...)
      {
      ill_date_exc = true;
      }
   CHECK(ill_date_exc);

   bool ill_date_exc2 = false;
   try
      {
      ASN1_Ced("2100 01 01");
      }
   catch (...)
      {
      ill_date_exc2 = true;
      }
   CHECK(ill_date_exc2);
   //cout << "readable = '" << cert_in.get_ced().readable_string() << "'\n";
   std::auto_ptr<Public_Key> p_pk(cert_in.subject_public_key());
   //auto_ptr<ECDSA_PublicKey> ecdsa_pk(dynamic_cast<auto_ptr<ECDSA_PublicKey> >(p_pk));
   ECDSA_PublicKey* p_ecdsa_pk = dynamic_cast<ECDSA_PublicKey*>(p_pk.get());
   // let´s see if encoding is truely implicitca, because this is what the key should have
   // been set to when decoding (see above)(because it has no domain params):
   //cout << "encoding = " << p_ecdsa_pk->get_parameter_encoding() << std::endl;
   CHECK(p_ecdsa_pk->domain_format() == EC_DOMPAR_ENC_IMPLICITCA);
   bool exc = false;
   try
      {
      std::cout << "order = " << p_ecdsa_pk->domain().get_order() << std::endl;
      }
   catch (Invalid_State)
      {
      exc = true;
      }
   CHECK(exc);
   // set them and try again
   //cert_in.set_domain_parameters(dom_pars);
   std::auto_ptr<Public_Key> p_pk2(cert_in.subject_public_key());
   ECDSA_PublicKey* p_ecdsa_pk2 = dynamic_cast<ECDSA_PublicKey*>(p_pk2.get());
   //p_ecdsa_pk2->set_domain_parameters(dom_pars);
   CHECK(p_ecdsa_pk2->domain().get_order() == dom_pars.get_order());
   bool ver_ec = cert_in.check_signature(*p_pk2);
   CHECK_MESSAGE(ver_ec, "could not positively verify correct selfsigned cvc certificate");
   }

void test_enc_gen_req(RandomNumberGenerator& rng)
   {
   std::cout << "." << std::flush;

   EAC1_1_CVC_Options opts;

   //opts.cpi = 0;
   opts.chr = ASN1_Chr("my_opt_chr");
   opts.hash_alg = "SHA-160";

   // creating a non sense selfsigned cert w/o dom pars
   EC_Group dom_pars(OID("1.3.132.0.8"));
   ECDSA_PrivateKey key(rng, dom_pars);
   key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
   EAC1_1_Req req = CVC_EAC::create_cvc_req(key, opts.chr, opts.hash_alg, rng);
   SecureVector<byte> der(req.BER_encode());
   std::ofstream req_file(TEST_DATA_DIR "/my_cv_req.ber", std::ios::binary);
   req_file.write((char*)&der[0], der.size());
   req_file.close();

   // read and check signature...
   EAC1_1_Req req_in(TEST_DATA_DIR "/my_cv_req.ber");
   //req_in.set_domain_parameters(dom_pars);
   std::auto_ptr<Public_Key> p_pk(req_in.subject_public_key());
   ECDSA_PublicKey* p_ecdsa_pk = dynamic_cast<ECDSA_PublicKey*>(p_pk.get());
   //p_ecdsa_pk->set_domain_parameters(dom_pars);
   CHECK(p_ecdsa_pk->domain().get_order() == dom_pars.get_order());
   bool ver_ec = req_in.check_signature(*p_pk);
   CHECK_MESSAGE(ver_ec, "could not positively verify correct selfsigned (created by myself) cvc request");
   }

void test_cvc_req_ext(RandomNumberGenerator&)
   {
   std::cout << "." << std::flush;

   EAC1_1_Req req_in(TEST_DATA_DIR "/DE1_flen_chars_cvcRequest_ECDSA.der");
   EC_Group dom_pars(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
   //req_in.set_domain_parameters(dom_pars);
   std::auto_ptr<Public_Key> p_pk(req_in.subject_public_key());
   ECDSA_PublicKey* p_ecdsa_pk = dynamic_cast<ECDSA_PublicKey*>(p_pk.get());
   //p_ecdsa_pk->set_domain_parameters(dom_pars);
   CHECK(p_ecdsa_pk->domain().get_order() == dom_pars.get_order());
   bool ver_ec = req_in.check_signature(*p_pk);
   CHECK_MESSAGE(ver_ec, "could not positively verify correct selfsigned (external testdata) cvc request");
   }

void test_cvc_ado_ext(RandomNumberGenerator&)
   {
   std::cout << "." << std::flush;

   EAC1_1_ADO req_in(TEST_DATA_DIR "/ado.cvcreq");
   EC_Group dom_pars(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
   //cout << "car = " << req_in.get_car().value() << std::endl;
   //req_in.set_domain_parameters(dom_pars);
   }

void test_cvc_ado_creation(RandomNumberGenerator& rng)
   {
   std::cout << "." << std::flush;

   EAC1_1_CVC_Options opts;
   //opts.cpi = 0;
   opts.chr = ASN1_Chr("my_opt_chr");
   opts.hash_alg = "SHA-256";

   // creating a non sense selfsigned cert w/o dom pars
   EC_Group dom_pars(OID("1.3.36.3.3.2.8.1.1.11"));
   //cout << "mod = " << hex << dom_pars.get_curve().get_p() << std::endl;
   ECDSA_PrivateKey req_key(rng, dom_pars);
   req_key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
   //EAC1_1_Req req = CVC_EAC::create_cvc_req(req_key, opts);
   EAC1_1_Req req = CVC_EAC::create_cvc_req(req_key, opts.chr, opts.hash_alg, rng);
   SecureVector<byte> der(req.BER_encode());
   std::ofstream req_file(TEST_DATA_DIR "/my_cv_req.ber", std::ios::binary);
   req_file.write((char*)&der[0], der.size());
   req_file.close();

   // create an ado with that req
   ECDSA_PrivateKey ado_key(rng, dom_pars);
   EAC1_1_CVC_Options ado_opts;
   ado_opts.car = ASN1_Car("my_ado_car");
   ado_opts.hash_alg = "SHA-256"; // must be equal to req´s hash alg, because ado takes his sig_algo from it´s request

   //EAC1_1_ADO ado = CVC_EAC::create_ado_req(ado_key, req, ado_opts);
   EAC1_1_ADO ado = CVC_EAC::create_ado_req(ado_key, req, ado_opts.car, rng);
   CHECK_MESSAGE(ado.check_signature(ado_key), "failure of ado verification after creation");

   std::ofstream ado_file(TEST_DATA_DIR "/ado", std::ios::binary);
   SecureVector<byte> ado_der(ado.BER_encode());
   ado_file.write((char*)&ado_der[0], ado_der.size());
   ado_file.close();
   // read it again and check the signature
   EAC1_1_ADO ado2(TEST_DATA_DIR "/ado");
   CHECK(ado == ado2);
   //ECDSA_PublicKey* p_ado_pk = dynamic_cast<ECDSA_PublicKey*>(&ado_key);
   //bool ver = ado2.check_signature(*p_ado_pk);
   bool ver = ado2.check_signature(ado_key);
   CHECK_MESSAGE(ver, "failure of ado verification after reloading");
   }

void test_cvc_ado_comparison(RandomNumberGenerator& rng)
   {
   std::cout << "." << std::flush;

   EAC1_1_CVC_Options opts;
   //opts.cpi = 0;
   opts.chr = ASN1_Chr("my_opt_chr");
   opts.hash_alg = "SHA-224";

   // creating a non sense selfsigned cert w/o dom pars
   EC_Group dom_pars(OID("1.3.36.3.3.2.8.1.1.11"));
   ECDSA_PrivateKey req_key(rng, dom_pars);
   req_key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
   //EAC1_1_Req req = CVC_EAC::create_cvc_req(req_key, opts);
   EAC1_1_Req req = CVC_EAC::create_cvc_req(req_key, opts.chr, opts.hash_alg, rng);


   // create an ado with that req
   ECDSA_PrivateKey ado_key(rng, dom_pars);
   EAC1_1_CVC_Options ado_opts;
   ado_opts.car = ASN1_Car("my_ado_car1");
   ado_opts.hash_alg = "SHA-224"; // must be equal to req's hash alg, because ado takes his sig_algo from it's request
   //EAC1_1_ADO ado = CVC_EAC::create_ado_req(ado_key, req, ado_opts);
   EAC1_1_ADO ado = CVC_EAC::create_ado_req(ado_key, req, ado_opts.car, rng);
   CHECK_MESSAGE(ado.check_signature(ado_key), "failure of ado verification after creation");
   // make a second one for comparison
   EAC1_1_CVC_Options opts2;
   //opts2.cpi = 0;
   opts2.chr = ASN1_Chr("my_opt_chr");
   opts2.hash_alg = "SHA-160"; // this is the only difference
   ECDSA_PrivateKey req_key2(rng, dom_pars);
   req_key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
   //EAC1_1_Req req2 = CVC_EAC::create_cvc_req(req_key2, opts2, rng);
   EAC1_1_Req req2 = CVC_EAC::create_cvc_req(req_key2, opts2.chr, opts2.hash_alg, rng);
   ECDSA_PrivateKey ado_key2(rng, dom_pars);
   EAC1_1_CVC_Options ado_opts2;
   ado_opts2.car = ASN1_Car("my_ado_car1");
   ado_opts2.hash_alg = "SHA-160"; // must be equal to req's hash alg, because ado takes his sig_algo from it's request

   EAC1_1_ADO ado2 = CVC_EAC::create_ado_req(ado_key2, req2, ado_opts2.car, rng);
   CHECK_MESSAGE(ado2.check_signature(ado_key2), "failure of ado verification after creation");

   CHECK_MESSAGE(ado != ado2, "ado's found to be equal where they are not");
   //     std::ofstream ado_file(TEST_DATA_DIR "/ado");
   //     SecureVector<byte> ado_der(ado.BER_encode());
   //     ado_file.write((char*)&ado_der[0], ado_der.size());
   //     ado_file.close();
   // read it again and check the signature

   //    EAC1_1_ADO ado2(TEST_DATA_DIR "/ado");
   //    ECDSA_PublicKey* p_ado_pk = dynamic_cast<ECDSA_PublicKey*>(&ado_key);
   //    //bool ver = ado2.check_signature(*p_ado_pk);
   //    bool ver = ado2.check_signature(ado_key);
   //    CHECK_MESSAGE(ver, "failure of ado verification after reloading");
   }

void test_eac_time(RandomNumberGenerator&)
   {
   std::cout << "." << std::flush;

   const u64bit current_time = system_time();
   EAC_Time time(current_time);
   //     std::cout << "time as std::string = " << time.as_string() << std::endl;
   EAC_Time sooner("", ASN1_Tag(99));
   //X509_Time sooner("", ASN1_Tag(99));
   sooner.set_to("2007 12 12");
   //     std::cout << "sooner as std::string = " << sooner.as_string() << std::endl;
   EAC_Time later("2007 12 13");
   //X509_Time later("2007 12 13");
   //     std::cout << "later as std::string = " << later.as_string() << std::endl;
   CHECK(sooner <= later);
   CHECK(sooner == sooner);

   ASN1_Cex my_cex("2007 08 01");
   my_cex.add_months(12);
   CHECK(my_cex.get_year() == 2008);
   CHECK_MESSAGE(my_cex.get_month() == 8, "shoult be 8, was " << my_cex.get_month());

   my_cex.add_months(4);
   CHECK(my_cex.get_year() == 2008);
   CHECK(my_cex.get_month() == 12);

   my_cex.add_months(4);
   CHECK(my_cex.get_year() == 2009);
   CHECK(my_cex.get_month() == 4);

   my_cex.add_months(41);
   CHECK(my_cex.get_year() == 2012);
   CHECK(my_cex.get_month() == 9);



   }

void test_ver_cvca(RandomNumberGenerator&)
   {
   std::cout << "." << std::flush;

   EAC1_1_CVC req_in(TEST_DATA_DIR "/cvca01.cv.crt");

   //auto_ptr<ECDSA_PublicKey> ecdsa_pk(dynamic_cast<auto_ptr<ECDSA_PublicKey> >(p_pk));
   //ECDSA_PublicKey* p_ecdsa_pk = dynamic_cast<ECDSA_PublicKey*>(p_pk.get());
   bool exc = false;

   std::auto_ptr<Public_Key> p_pk2(req_in.subject_public_key());
   ECDSA_PublicKey* p_ecdsa_pk2 = dynamic_cast<ECDSA_PublicKey*>(p_pk2.get());
   bool ver_ec = req_in.check_signature(*p_pk2);
   CHECK_MESSAGE(ver_ec, "could not positively verify correct selfsigned cvca certificate");

   try
      {
      p_ecdsa_pk2->domain().get_order();
      }
   catch (Invalid_State)
      {
      exc = true;
      }
   CHECK(!exc);
   }

void test_copy_and_assignment(RandomNumberGenerator&)
   {
   std::cout << "." << std::flush;

   EAC1_1_CVC cert_in(TEST_DATA_DIR "/cvca01.cv.crt");
   EAC1_1_CVC cert_cp(cert_in);
   EAC1_1_CVC cert_ass = cert_in;
   CHECK(cert_in == cert_cp);
   CHECK(cert_in == cert_ass);

   EAC1_1_ADO ado_in(TEST_DATA_DIR "/ado.cvcreq");
   //EC_Group dom_pars(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
   EAC1_1_ADO ado_cp(ado_in);
   EAC1_1_ADO ado_ass = ado_in;
   CHECK(ado_in == ado_cp);
   CHECK(ado_in == ado_ass);

   EAC1_1_Req req_in(TEST_DATA_DIR "/DE1_flen_chars_cvcRequest_ECDSA.der");
   //EC_Group dom_pars(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
   EAC1_1_Req req_cp(req_in);
   EAC1_1_Req req_ass = req_in;
   CHECK(req_in == req_cp);
   CHECK(req_in == req_ass);
   }

void test_eac_str_illegal_values(RandomNumberGenerator&)
   {
   std::cout << "." << std::flush;

   bool exc = false;
   try
      {
      EAC1_1_CVC(TEST_DATA_DIR "/cvca_illegal_chars.cv.crt");

      }
   catch (Decoding_Error)
      {
      exc = true;
      }
   CHECK(exc);

   bool exc2 = false;
   try
      {
      EAC1_1_CVC(TEST_DATA_DIR "/cvca_illegal_chars2.cv.crt");

      }
   catch (Decoding_Error)
      {
      exc2 = true;
      }
   CHECK(exc2);
   }

void test_tmp_eac_str_enc(RandomNumberGenerator&)
   {
   std::cout << "." << std::flush;

   bool exc = false;
   try
      {
      ASN1_Car("abc!+-µ\n");
      }
   catch (Invalid_Argument)
      {
      exc = true;
      }
   CHECK(exc);
   //     std::string val = car.iso_8859();
   //     std::cout << "car 8859 = " << val << std::endl;
   //     std::cout << hex <<(unsigned char)val[1] << std::endl;


   }

void test_cvc_chain(RandomNumberGenerator& rng)
   {
   std::cout << "." << std::flush;

   EC_Group dom_pars(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
   ECDSA_PrivateKey cvca_privk(rng, dom_pars);
   std::string hash("SHA-224");
   ASN1_Car car("DECVCA00001");
   EAC1_1_CVC cvca_cert = DE_EAC::create_cvca(cvca_privk, hash, car, true, true, 12, rng);
   std::ofstream cvca_file(TEST_DATA_DIR "/cvc_chain_cvca.cer", std::ios::binary);
   SecureVector<byte> cvca_sv = cvca_cert.BER_encode();
   cvca_file.write((char*)&cvca_sv[0], cvca_sv.size());
   cvca_file.close();

   ECDSA_PrivateKey cvca_privk2(rng, dom_pars);
   ASN1_Car car2("DECVCA00002");
   EAC1_1_CVC cvca_cert2 = DE_EAC::create_cvca(cvca_privk2, hash, car2, true, true, 12, rng);
   EAC1_1_CVC link12 = DE_EAC::link_cvca(cvca_cert, cvca_privk, cvca_cert2, rng);
   SecureVector<byte> link12_sv = link12.BER_encode();
   std::ofstream link12_file(TEST_DATA_DIR "/cvc_chain_link12.cer", std::ios::binary);
   link12_file.write((char*)&link12_sv[0], link12_sv.size());
   link12_file.close();

   // verify the link
   CHECK(link12.check_signature(cvca_privk));
   EAC1_1_CVC link12_reloaded(TEST_DATA_DIR "/cvc_chain_link12.cer");
   EAC1_1_CVC cvca1_reloaded(TEST_DATA_DIR "/cvc_chain_cvca.cer");
   std::auto_ptr<Public_Key> cvca1_rel_pk(cvca1_reloaded.subject_public_key());
   CHECK(link12_reloaded.check_signature(*cvca1_rel_pk));

   // create first round dvca-req
   ECDSA_PrivateKey dvca_priv_key(rng, dom_pars);
   EAC1_1_Req dvca_req = DE_EAC::create_cvc_req(dvca_priv_key, ASN1_Chr("DEDVCAEPASS"), hash, rng);
   std::ofstream dvca_file(TEST_DATA_DIR "/cvc_chain_dvca_req.cer", std::ios::binary);
   SecureVector<byte> dvca_sv = dvca_req.BER_encode();
   dvca_file.write((char*)&dvca_sv[0], dvca_sv.size());
   dvca_file.close();

   // sign the dvca_request
   EAC1_1_CVC dvca_cert1 = DE_EAC::sign_request(cvca_cert, cvca_privk, dvca_req, 1, 5, true, 3, 1, rng);
   CHECK(dvca_cert1.get_car().iso_8859() == "DECVCA00001");
   CHECK(dvca_cert1.get_chr().iso_8859() == "DEDVCAEPASS00001");
   helper_write_file(dvca_cert1, TEST_DATA_DIR "/cvc_chain_dvca_cert1.cer");

   // make a second round dvca ado request
   ECDSA_PrivateKey dvca_priv_key2(rng, dom_pars);
   EAC1_1_Req dvca_req2 = DE_EAC::create_cvc_req(dvca_priv_key2, ASN1_Chr("DEDVCAEPASS"), hash, rng);
   std::ofstream dvca_file2(TEST_DATA_DIR "/cvc_chain_dvca_req2.cer", std::ios::binary);
   SecureVector<byte> dvca_sv2 = dvca_req2.BER_encode();
   dvca_file2.write((char*)&dvca_sv2[0], dvca_sv2.size());
   dvca_file2.close();
   EAC1_1_ADO dvca_ado2 = CVC_EAC::create_ado_req(dvca_priv_key, dvca_req2,
                                                  ASN1_Car(dvca_cert1.get_chr().iso_8859()), rng);
   helper_write_file(dvca_ado2, TEST_DATA_DIR "/cvc_chain_dvca_ado2.cer");

   // verify the ado and sign the request too

   std::auto_ptr<Public_Key> ap_pk(dvca_cert1.subject_public_key());
   ECDSA_PublicKey* cert_pk = dynamic_cast<ECDSA_PublicKey*>(ap_pk.get());

   //cert_pk->set_domain_parameters(dom_pars);
   //std::cout << "dvca_cert.public_point.size() = " << ec::EC2OSP(cert_pk->get_public_point(), ec::PointGFp::COMPRESSED).size() << std::endl;
   EAC1_1_CVC dvca_cert1_reread(TEST_DATA_DIR "/cvc_chain_cvca.cer");
   CHECK(dvca_ado2.check_signature(*cert_pk));

   CHECK(dvca_ado2.check_signature(dvca_priv_key)); // must also work

   EAC1_1_Req dvca_req2b = dvca_ado2.get_request();
   helper_write_file(dvca_req2b, TEST_DATA_DIR "/cvc_chain_dvca_req2b.cer");
   CHECK(helper_files_equal(TEST_DATA_DIR "/cvc_chain_dvca_req2b.cer", TEST_DATA_DIR "/cvc_chain_dvca_req2.cer"));
   EAC1_1_CVC dvca_cert2 = DE_EAC::sign_request(cvca_cert, cvca_privk, dvca_req2b, 2, 5, true, 3, 1, rng);
   CHECK(dvca_cert2.get_car().iso_8859() == "DECVCA00001");
   CHECK_MESSAGE(dvca_cert2.get_chr().iso_8859() == "DEDVCAEPASS00002",
                 "chr = " << dvca_cert2.get_chr().iso_8859());

   // make a first round IS request
   ECDSA_PrivateKey is_priv_key(rng, dom_pars);
   EAC1_1_Req is_req = DE_EAC::create_cvc_req(is_priv_key, ASN1_Chr("DEIS"), hash, rng);
   helper_write_file(is_req, TEST_DATA_DIR "/cvc_chain_is_req.cer");

   // sign the IS request
   //dvca_cert1.set_domain_parameters(dom_pars);
   EAC1_1_CVC is_cert1 = DE_EAC::sign_request(dvca_cert1, dvca_priv_key, is_req, 1, 5, true, 3, 1, rng);
   CHECK_MESSAGE(is_cert1.get_car().iso_8859() == "DEDVCAEPASS00001", "car = " << is_cert1.get_car().iso_8859());
   CHECK(is_cert1.get_chr().iso_8859() == "DEIS00001");
   helper_write_file(is_cert1, TEST_DATA_DIR "/cvc_chain_is_cert.cer");

   // verify the signature of the certificate
   CHECK(is_cert1.check_signature(dvca_priv_key));
   }

}

u32bit do_cvc_tests(Botan::RandomNumberGenerator& rng)
   {
   std::cout << "Testing CVC: " << std::flush;

   test_enc_gen_selfsigned(rng);
   test_enc_gen_req(rng);
   test_cvc_req_ext(rng);
   test_cvc_ado_ext(rng);
   test_cvc_ado_creation(rng);
   test_cvc_ado_comparison(rng);
   test_eac_time(rng);
   test_ver_cvca(rng);
   test_copy_and_assignment(rng);
   test_eac_str_illegal_values(rng);
   test_tmp_eac_str_enc(rng);
   test_cvc_chain(rng);
   std::cout << std::endl;

   return 0;
   }
#else
u32bit do_cvc_tests(Botan::RandomNumberGenerator&) { return 0; }
#endif
