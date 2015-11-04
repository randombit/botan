/*
* CVC EAC1.1 tests
*
* (C) 2008 Falko Strenzke (strenzke@flexsecure.de)
*     2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <iostream>
#include <iterator>
#include <algorithm>
#include <fstream>
#include <vector>
#include <memory>

#if defined(BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES)

#include <botan/ecdsa.h>
#include <botan/x509cert.h>
#include <botan/x509self.h>
#include <botan/oids.h>
#include <botan/cvc_self.h>
#include <botan/cvc_cert.h>
#include <botan/cvc_ado.h>

#define CVC_TEST_DATA_DIR TEST_DATA_DIR "/ecc"

#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES)

using namespace Botan;

// helper functions
void helper_write_file(EAC_Signed_Object const& to_write, const std::string& file_path)
   {
   std::vector<byte> sv = to_write.BER_encode();
   std::ofstream cert_file(file_path, std::ios::binary);
   cert_file.write((char*)sv.data(), sv.size());
   cert_file.close();
   }

bool helper_files_equal(const std::string& file_path1, const std::string& file_path2)
   {
   std::ifstream cert_1_in(file_path1);
   std::ifstream cert_2_in(file_path2);
   std::vector<byte> sv1;
   std::vector<byte> sv2;
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

Test::Result test_enc_gen_selfsigned()
   {
   Test::Result result("CVC");

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
   ECDSA_PrivateKey key(Test::rng(), dom_pars);
   key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
   EAC1_1_CVC cert = CVC_EAC::create_self_signed_cert(key, opts, Test::rng());

   std::vector<byte> der(cert.BER_encode());
   std::ofstream cert_file;
   cert_file.open(CVC_TEST_DATA_DIR "/my_cv_cert.ber", std::ios::binary);
   cert_file.write((char*)der.data(), der.size());
   cert_file.close();

   EAC1_1_CVC cert_in(CVC_TEST_DATA_DIR "/my_cv_cert.ber");
   result.confirm("reloaded cert matches", cert_in == cert);

   // encoding it again while it has no dp
   std::vector<byte> der2(cert_in.BER_encode());
   std::ofstream cert_file2(CVC_TEST_DATA_DIR "/my_cv_cert2.ber", std::ios::binary);
   cert_file2.write((char*)der2.data(), der2.size());
   cert_file2.close();

   // read both and compare them
   std::ifstream cert_1_in(CVC_TEST_DATA_DIR "/my_cv_cert.ber");
   std::ifstream cert_2_in(CVC_TEST_DATA_DIR "/my_cv_cert2.ber");
   std::vector<byte> sv1;
   std::vector<byte> sv2;
   if (!cert_1_in || cert_2_in)
      {
      result.test_failure("Unable to reread cert files");
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

   result.test_gte("size", sv1.size(), 10);
   result.test_ne("reencoded file of cert without domain parameters is different from original", sv1, sv2);

   //cout << "reading cert again" << std::endl;
   result.test_eq("car", cert_in.get_car().value(), "my_opt_car");
   result.test_eq("chr", cert_in.get_chr().value(), "my_opt_car");
   result.test_eq("ced", cert_in.get_ced().as_string(), "20100727");
   result.test_eq("ced", cert_in.get_ced().readable_string(), "2010/07/27");

   try
      {
      ASN1_Ced invalid("1999 01 01");
      result.test_failure("Allowed creation of invalid 1999 ASN1_Ced");
      }
   catch(...) {}

   try
      {
      ASN1_Ced("2100 01 01");
      result.test_failure("Allowed creation of invalid 2100 ASN1_Ced");
      }
   catch(...) {}

   std::unique_ptr<Public_Key> p_pk(cert_in.subject_public_key());
   ECDSA_PublicKey* p_ecdsa_pk = dynamic_cast<ECDSA_PublicKey*>(p_pk.get());

   // let's see if encoding is truely implicitca, because this is what the key should have
   // been set to when decoding (see above)(because it has no domain params):

   result.confirm("implicit CA", p_ecdsa_pk->domain_format() == EC_DOMPAR_ENC_IMPLICITCA);

   try
      {
      std::cout << "order = " << p_ecdsa_pk->domain().get_order() << std::endl;
      result.test_failure("Expected accessing domain to fail");
      }
   catch (Invalid_State) {}
      {
      }

   // set them and try again
   //cert_in.set_domain_parameters(dom_pars);
   std::unique_ptr<Public_Key> p_pk2(cert_in.subject_public_key());
   ECDSA_PublicKey* p_ecdsa_pk2 = dynamic_cast<ECDSA_PublicKey*>(p_pk2.get());
   //p_ecdsa_pk2->set_domain_parameters(dom_pars);
   result.test_eq("order", p_ecdsa_pk2->domain().get_order(), dom_pars.get_order());
   result.confirm("verified signature", cert_in.check_signature(*p_pk2));

   return result;
   }

Test::Result test_enc_gen_req()
   {
   Test::Result result("CVC");

   EAC1_1_CVC_Options opts;

   //opts.cpi = 0;
   opts.chr = ASN1_Chr("my_opt_chr");
   opts.hash_alg = "SHA-160";

   // creating a non sense selfsigned cert w/o dom pars
   EC_Group dom_pars(OID("1.3.132.0.8"));
   ECDSA_PrivateKey key(Test::rng(), dom_pars);
   key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
   EAC1_1_Req req = CVC_EAC::create_cvc_req(key, opts.chr, opts.hash_alg, Test::rng());
   std::vector<byte> der(req.BER_encode());
   std::ofstream req_file(CVC_TEST_DATA_DIR "/my_cv_req.ber", std::ios::binary);
   req_file.write((char*)der.data(), der.size());
   req_file.close();

   // read and check signature...
   EAC1_1_Req req_in(CVC_TEST_DATA_DIR "/my_cv_req.ber");
   //req_in.set_domain_parameters(dom_pars);
   std::unique_ptr<Public_Key> p_pk(req_in.subject_public_key());
   ECDSA_PublicKey* p_ecdsa_pk = dynamic_cast<ECDSA_PublicKey*>(p_pk.get());
   //p_ecdsa_pk->set_domain_parameters(dom_pars);
   result.test_eq("order", p_ecdsa_pk->domain().get_order(), dom_pars.get_order());
   result.confirm("signature valid on CVC request", req_in.check_signature(*p_pk));

   return result;
   }

Test::Result test_cvc_req_ext()
   {
   EAC1_1_Req req_in(CVC_TEST_DATA_DIR "/DE1_flen_chars_cvcRequest_ECDSA.der");
   EC_Group dom_pars(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
   //req_in.set_domain_parameters(dom_pars);
   std::unique_ptr<Public_Key> p_pk(req_in.subject_public_key());
   ECDSA_PublicKey* p_ecdsa_pk = dynamic_cast<ECDSA_PublicKey*>(p_pk.get());

   Test::Result result("CVC");
   result.test_eq("order", p_ecdsa_pk->domain().get_order(), dom_pars.get_order());
   result.confirm("signature valid on CVC request", req_in.check_signature(*p_pk));
   return result;
   }

Test::Result test_cvc_ado_creation()
   {
   Test::Result result("CVC");

   EAC1_1_CVC_Options opts;
   //opts.cpi = 0;
   opts.chr = ASN1_Chr("my_opt_chr");
   opts.hash_alg = "SHA-256";

   // creating a non sense selfsigned cert w/o dom pars
   EC_Group dom_pars(OID("1.3.36.3.3.2.8.1.1.11"));
   //cout << "mod = " << hex << dom_pars.get_curve().get_p() << std::endl;
   ECDSA_PrivateKey req_key(Test::rng(), dom_pars);
   req_key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
   //EAC1_1_Req req = CVC_EAC::create_cvc_req(req_key, opts);
   EAC1_1_Req req = CVC_EAC::create_cvc_req(req_key, opts.chr, opts.hash_alg, Test::rng());
   std::vector<byte> der(req.BER_encode());
   std::ofstream req_file(CVC_TEST_DATA_DIR "/my_cv_req.ber", std::ios::binary);
   req_file.write((char*)der.data(), der.size());
   req_file.close();

   // create an ado with that req
   ECDSA_PrivateKey ado_key(Test::rng(), dom_pars);
   EAC1_1_CVC_Options ado_opts;
   ado_opts.car = ASN1_Car("my_ado_car");
   ado_opts.hash_alg = "SHA-256"; // must be equal to req's hash alg, because ado takes his sig_algo from it's request

   //EAC1_1_ADO ado = CVC_EAC::create_ado_req(ado_key, req, ado_opts);
   EAC1_1_ADO ado = CVC_EAC::create_ado_req(ado_key, req, ado_opts.car, Test::rng());
   result.confirm("ADO signature verifies", ado.check_signature(ado_key));

   std::ofstream ado_file(CVC_TEST_DATA_DIR "/ado", std::ios::binary);
   std::vector<byte> ado_der(ado.BER_encode());
   ado_file.write((char*)ado_der.data(), ado_der.size());
   ado_file.close();
   // read it again and check the signature
   EAC1_1_ADO ado2(CVC_TEST_DATA_DIR "/ado");
   result.confirm("ADOs match", ado == ado2);

   result.confirm("ADO signature valid", ado2.check_signature(ado_key));

   return result;
   }

Test::Result test_cvc_ado_comparison()
   {
   Test::Result result("CVC");

   EAC1_1_CVC_Options opts;
   //opts.cpi = 0;
   opts.chr = ASN1_Chr("my_opt_chr");
   opts.hash_alg = "SHA-224";

   // creating a non sense selfsigned cert w/o dom pars
   EC_Group dom_pars(OID("1.3.36.3.3.2.8.1.1.11"));
   ECDSA_PrivateKey req_key(Test::rng(), dom_pars);
   req_key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
   //EAC1_1_Req req = CVC_EAC::create_cvc_req(req_key, opts);
   EAC1_1_Req req = CVC_EAC::create_cvc_req(req_key, opts.chr, opts.hash_alg, Test::rng());


   // create an ado with that req
   ECDSA_PrivateKey ado_key(Test::rng(), dom_pars);
   EAC1_1_CVC_Options ado_opts;
   ado_opts.car = ASN1_Car("my_ado_car1");
   ado_opts.hash_alg = "SHA-224"; // must be equal to req's hash alg, because ado takes his sig_algo from it's request
   //EAC1_1_ADO ado = CVC_EAC::create_ado_req(ado_key, req, ado_opts);
   EAC1_1_ADO ado = CVC_EAC::create_ado_req(ado_key, req, ado_opts.car, Test::rng());
   result.confirm("ADO signature valid", ado.check_signature(ado_key));
   // make a second one for comparison
   EAC1_1_CVC_Options opts2;
   //opts2.cpi = 0;
   opts2.chr = ASN1_Chr("my_opt_chr");
   opts2.hash_alg = "SHA-160"; // this is the only difference
   ECDSA_PrivateKey req_key2(Test::rng(), dom_pars);
   req_key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
   //EAC1_1_Req req2 = CVC_EAC::create_cvc_req(req_key2, opts2, Test::rng());
   EAC1_1_Req req2 = CVC_EAC::create_cvc_req(req_key2, opts2.chr, opts2.hash_alg, Test::rng());
   ECDSA_PrivateKey ado_key2(Test::rng(), dom_pars);
   EAC1_1_CVC_Options ado_opts2;
   ado_opts2.car = ASN1_Car("my_ado_car1");
   ado_opts2.hash_alg = "SHA-160"; // must be equal to req's hash alg, because ado takes his sig_algo from it's request

   EAC1_1_ADO ado2 = CVC_EAC::create_ado_req(ado_key2, req2, ado_opts2.car, Test::rng());
   result.confirm("ADO signature after creation", ado2.check_signature(ado_key2));

   result.confirm("ADOs should not be equal", ado != ado2);
   //     std::ofstream ado_file(CVC_TEST_DATA_DIR "/ado");
   //     std::vector<byte> ado_der(ado.BER_encode());
   //     ado_file.write((char*)ado_der.data(), ado_der.size());
   //     ado_file.close();
   // read it again and check the signature

   //    EAC1_1_ADO ado2(CVC_TEST_DATA_DIR "/ado");
   //    ECDSA_PublicKey* p_ado_pk = dynamic_cast<ECDSA_PublicKey*>(&ado_key);
   //    //bool ver = ado2.check_signature(*p_ado_pk);
   //    bool ver = ado2.check_signature(ado_key);
   //    CHECK_MESSAGE(ver, "failure of ado verification after reloading");

   return result;
   }

void confirm_cex_time(Test::Result& result,
                      const ASN1_Cex& cex,
                      size_t exp_year,
                      size_t exp_month)
   {
   result.test_eq("year", cex.get_year(), exp_year);
   result.test_eq("month", cex.get_month(), exp_month);
   }

Test::Result test_eac_time()
   {
   Test::Result result("CVC");

   EAC_Time sooner("", ASN1_Tag(99));
   sooner.set_to("2007 12 12");
   EAC_Time later("2007 12 13");

   result.confirm("sooner < later", sooner < later);
   result.confirm("self-equal", sooner == sooner);

   ASN1_Cex my_cex("2007 08 01");
   my_cex.add_months(12);
   confirm_cex_time(result, my_cex, 2008, 8);

   my_cex.add_months(4);
   confirm_cex_time(result, my_cex, 2008, 12);

   my_cex.add_months(4);
   confirm_cex_time(result, my_cex, 2009, 4);

   my_cex.add_months(41);
   confirm_cex_time(result, my_cex, 2012, 9);

   return result;
   }

Test::Result test_ver_cvca()
   {
   Test::Result result("CVC");

   EAC1_1_CVC cvc(CVC_TEST_DATA_DIR "/cvca01.cv.crt");

   std::unique_ptr<Public_Key> p_pk2(cvc.subject_public_key());
   result.confirm("verified CVCA cert", cvc.check_signature(*p_pk2));

   try
      {
      ECDSA_PublicKey* p_ecdsa_pk2 = dynamic_cast<ECDSA_PublicKey*>(p_pk2.get());
      p_ecdsa_pk2->domain().get_order();
      result.test_failure("Expected failure");
      }
   catch(Invalid_State)
      {
      result.test_note("Accessing order failed");
      }

   return result;
   }

Test::Result test_copy_and_assignment()
   {
   Test::Result result("CVC");

   EAC1_1_CVC cert_in(CVC_TEST_DATA_DIR "/cvca01.cv.crt");
   EAC1_1_CVC cert_cp(cert_in);
   EAC1_1_CVC cert_ass = cert_in;

   result.confirm("same cert", cert_in == cert_cp);
   result.confirm("same cert", cert_in == cert_ass);

   EAC1_1_ADO ado_in(CVC_TEST_DATA_DIR "/ado.cvcreq");
   EAC1_1_ADO ado_cp(ado_in);
   EAC1_1_ADO ado_ass = ado_in;
   result.confirm("same", ado_in == ado_cp);
   result.confirm("same", ado_in == ado_ass);

   EAC1_1_Req req_in(CVC_TEST_DATA_DIR "/DE1_flen_chars_cvcRequest_ECDSA.der");
   EAC1_1_Req req_cp(req_in);
   EAC1_1_Req req_ass = req_in;
   result.confirm("same", req_in == req_cp);
   result.confirm("same", req_in == req_ass);

   return result;
   }

Test::Result test_eac_str_illegal_values()
   {
   Test::Result result("CVC");

   try
      {
      EAC1_1_CVC(CVC_TEST_DATA_DIR "/cvca_illegal_chars.cv.crt");
      result.test_failure("Accepted invalid EAC 1.1 CVC");
      }
   catch (Decoding_Error) {}

   try
      {
      EAC1_1_CVC(CVC_TEST_DATA_DIR "/cvca_illegal_chars2.cv.crt");
      result.test_failure("Accepted invalid EAC 1.1 CVC #2");
      }
   catch (Decoding_Error) {}

   return result;
   }

Test::Result test_tmp_eac_str_enc()
   {
   Test::Result result("CVC");
   try
      {
      ASN1_Car("abc!+-µ\n");
      result.test_failure("Accepted invalid EAC string");
      }
   catch(Invalid_Argument) {}

   return result;
   }

Test::Result test_cvc_chain()
   {
   Test::Result result("CVC");

   EC_Group dom_pars(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
   ECDSA_PrivateKey cvca_privk(Test::rng(), dom_pars);
   std::string hash("SHA-224");
   ASN1_Car car("DECVCA00001");
   EAC1_1_CVC cvca_cert = DE_EAC::create_cvca(cvca_privk, hash, car, true, true, 12, Test::rng());
   std::ofstream cvca_file(CVC_TEST_DATA_DIR "/cvc_chain_cvca.cer", std::ios::binary);
   std::vector<byte> cvca_sv = cvca_cert.BER_encode();
   cvca_file.write((char*)cvca_sv.data(), cvca_sv.size());
   cvca_file.close();

   ECDSA_PrivateKey cvca_privk2(Test::rng(), dom_pars);
   ASN1_Car car2("DECVCA00002");
   EAC1_1_CVC cvca_cert2 = DE_EAC::create_cvca(cvca_privk2, hash, car2, true, true, 12, Test::rng());
   EAC1_1_CVC link12 = DE_EAC::link_cvca(cvca_cert, cvca_privk, cvca_cert2, Test::rng());
   std::vector<byte> link12_sv = link12.BER_encode();
   std::ofstream link12_file(CVC_TEST_DATA_DIR "/cvc_chain_link12.cer", std::ios::binary);
   link12_file.write((char*)link12_sv.data(), link12_sv.size());
   link12_file.close();

   // verify the link
   result.confirm("signature valid", link12.check_signature(cvca_privk));
   EAC1_1_CVC link12_reloaded(CVC_TEST_DATA_DIR "/cvc_chain_link12.cer");
   EAC1_1_CVC cvca1_reloaded(CVC_TEST_DATA_DIR "/cvc_chain_cvca.cer");
   std::unique_ptr<Public_Key> cvca1_rel_pk(cvca1_reloaded.subject_public_key());
   result.confirm("signature valid", link12_reloaded.check_signature(*cvca1_rel_pk));

   // create first round dvca-req
   ECDSA_PrivateKey dvca_priv_key(Test::rng(), dom_pars);
   EAC1_1_Req dvca_req = DE_EAC::create_cvc_req(dvca_priv_key, ASN1_Chr("DEDVCAEPASS"), hash, Test::rng());
   std::ofstream dvca_file(CVC_TEST_DATA_DIR "/cvc_chain_dvca_req.cer", std::ios::binary);
   std::vector<byte> dvca_sv = dvca_req.BER_encode();
   dvca_file.write((char*)dvca_sv.data(), dvca_sv.size());
   dvca_file.close();

   // sign the dvca_request
   EAC1_1_CVC dvca_cert1 = DE_EAC::sign_request(cvca_cert, cvca_privk, dvca_req, 1, 5, true, 3, 1, Test::rng());
   result.test_eq("DVCA car", dvca_cert1.get_car().iso_8859(), "DECVCA00001");
   result.test_eq("DVCA chr", dvca_cert1.get_chr().iso_8859(), "DEDVCAEPASS00001");
   helper_write_file(dvca_cert1, CVC_TEST_DATA_DIR "/cvc_chain_dvca_cert1.cer");

   // make a second round dvca ado request
   ECDSA_PrivateKey dvca_priv_key2(Test::rng(), dom_pars);
   EAC1_1_Req dvca_req2 = DE_EAC::create_cvc_req(dvca_priv_key2, ASN1_Chr("DEDVCAEPASS"), hash, Test::rng());
   std::ofstream dvca_file2(CVC_TEST_DATA_DIR "/cvc_chain_dvca_req2.cer", std::ios::binary);
   std::vector<byte> dvca_sv2 = dvca_req2.BER_encode();
   dvca_file2.write((char*)dvca_sv2.data(), dvca_sv2.size());
   dvca_file2.close();
   EAC1_1_ADO dvca_ado2 = CVC_EAC::create_ado_req(dvca_priv_key, dvca_req2,
                                                  ASN1_Car(dvca_cert1.get_chr().iso_8859()), Test::rng());
   helper_write_file(dvca_ado2, CVC_TEST_DATA_DIR "/cvc_chain_dvca_ado2.cer");

   // verify the ado and sign the request too

   std::unique_ptr<Public_Key> ap_pk(dvca_cert1.subject_public_key());
   ECDSA_PublicKey* cert_pk = dynamic_cast<ECDSA_PublicKey*>(ap_pk.get());

   //cert_pk->set_domain_parameters(dom_pars);
   //std::cout << "dvca_cert.public_point.size() = " << ec::EC2OSP(cert_pk->get_public_point(), ec::PointGFp::COMPRESSED).size() << std::endl;
   EAC1_1_CVC dvca_cert1_reread(CVC_TEST_DATA_DIR "/cvc_chain_cvca.cer");
   result.confirm("signature valid", dvca_ado2.check_signature(*cert_pk));
   result.confirm("signature valid", dvca_ado2.check_signature(dvca_priv_key)); // must also work

   EAC1_1_Req dvca_req2b = dvca_ado2.get_request();
   helper_write_file(dvca_req2b, CVC_TEST_DATA_DIR "/cvc_chain_dvca_req2b.cer");
   result.confirm("files match", helper_files_equal(CVC_TEST_DATA_DIR "/cvc_chain_dvca_req2b.cer", CVC_TEST_DATA_DIR "/cvc_chain_dvca_req2.cer"));
   EAC1_1_CVC dvca_cert2 = DE_EAC::sign_request(cvca_cert, cvca_privk, dvca_req2b, 2, 5, true, 3, 1, Test::rng());
   result.test_eq("DVCA car", dvca_cert2.get_car().iso_8859(), "DECVCA00001");
   result.test_eq("DVCA chr", dvca_cert2.get_chr().iso_8859(), "DEDVCAEPASS00002");

   // make a first round IS request
   ECDSA_PrivateKey is_priv_key(Test::rng(), dom_pars);
   EAC1_1_Req is_req = DE_EAC::create_cvc_req(is_priv_key, ASN1_Chr("DEIS"), hash, Test::rng());
   helper_write_file(is_req, CVC_TEST_DATA_DIR "/cvc_chain_is_req.cer");

   // sign the IS request
   //dvca_cert1.set_domain_parameters(dom_pars);
   EAC1_1_CVC is_cert1 = DE_EAC::sign_request(dvca_cert1, dvca_priv_key, is_req, 1, 5, true, 3, 1, Test::rng());
   result.test_eq("EAC 1.1 CVC car", is_cert1.get_car().iso_8859(), "DEDVCAEPASS00001");
   result.test_eq("EAC 1.1 CVC chr", is_cert1.get_chr().iso_8859(), "DEIS00001");
   helper_write_file(is_cert1, CVC_TEST_DATA_DIR "/cvc_chain_is_cert.cer");

   // verify the signature of the certificate
   result.confirm("valid signature", is_cert1.check_signature(dvca_priv_key));

   return result;
   }

class CVC_Unit_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_enc_gen_selfsigned());
         results.push_back(test_enc_gen_req());
         results.push_back(test_cvc_req_ext());
         results.push_back(test_cvc_ado_creation());
         results.push_back(test_cvc_ado_comparison());
         results.push_back(test_eac_time());
         results.push_back(test_ver_cvca());
         results.push_back(test_copy_and_assignment());
         results.push_back(test_eac_str_illegal_values());
         results.push_back(test_tmp_eac_str_enc());
         results.push_back(test_cvc_chain());

         return results;
         }

   };

BOTAN_REGISTER_TEST("cvc", CVC_Unit_Tests);

#endif

}

}
