/******************************************************
* CVC EAC1.1 tests                                   *
*                                                    *
* (C) 2008 Falko Strenzke                            *
*          strenzke@flexsecure.de                    *
******************************************************/

#include <iosfwd>
#include <iostream>
#include <iterator>
#include <algorithm>
#include <fstream>
#include <vector>

#include <botan/math/ec/point_gfp.h>
#include <botan/math/ec/curve_gfp.h>
#include <botan/math/gf/gfp_element.h>
#include <botan/math/bigint.h>
#include <botan/math/mp_types.h>
#include <botan/math/bigintfuncs.h>
#include <botan/math/mp_types.h>
#include <botan/ec.h>
#include <botan/ec_dompar.h>
#include <botan/x509cert.h>
#include <botan/x509self.h>
#include <botan/oids.h>
#include <botan/look_pk.h>
#include <botan/rsa.h>
#include <botan/pubkey.h>
#include <botan/cvc_self.h>
#include <botan/cvc_cert.h>
#include <botan/asn1_obj.h>
#include <botan/util.h>
#include <botan/cvc_ado.h>
#include <botan/enums.h>
//using namespace Botan_types;
using namespace Botan::math;
using namespace Botan::math::gf;
using namespace Botan::math::ec;

// helper functions
void helper_write_file(Botan::Signed_Object const& to_write, string const& file_path)
{
  Botan::SecureVector<Botan::byte> sv = to_write.BER_encode();
  ofstream cert_file(file_path.c_str(), ios::binary);
  cert_file.write((char*)sv.begin(), sv.size());
  cert_file.close();
}

bool helper_files_equal(string const& file_path1, string const& file_path2)
{
  ifstream cert_1_in(file_path1.c_str());
  ifstream cert_2_in(file_path2.c_str());
  Botan::SecureVector<Botan::byte> sv1;
  Botan::SecureVector<Botan::byte> sv2;
  if (!cert_1_in || !cert_2_in)
    {
      return false;
    }
  while (!cert_1_in.eof())
    {
      char now;
      cert_1_in.read(&now, 1);
      sv1.append(now);
    }
  while (!cert_2_in.eof())
    {
      char now;
      cert_2_in.read(&now, 1);
      sv2.append(now);
    }
  if (sv1.size() == 0)
    {
      return false;
    }
  return sv1 == sv2;
}


BOOST_AUTO_TEST_CASE( test_enc_gen_selfsigned)
{
  cout << "." << flush;
  Botan::LibraryInitializer init;
  Botan::EAC1_1_CVC_Options opts;
//opts.cpi = 0;
  opts.chr = Botan::ASN1_Chr("my_opt_chr"); // not used
  opts.car = Botan::ASN1_Car("my_opt_car");
  opts.cex = Botan::ASN1_Cex("2010 08 13");
  opts.ced = Botan::ASN1_Ced("2010 07 27");
  opts.holder_auth_templ = 0xC1;
  opts.hash_alg = "SHA-256";

// creating a non sense selfsigned cert w/o dom pars
  Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.36.3.3.2.8.1.1.11"));
  Botan::ECDSA_PrivateKey key(dom_pars);
  key.set_parameter_encoding(Botan::ENC_IMPLICITCA);
  Botan::EAC1_1_CVC cert = Botan::CVC_EAC::create_self_signed_cert(key, opts);

  Botan::SecureVector<Botan::byte> der(cert.BER_encode());
  ofstream cert_file;
  cert_file.open("checks/temp/my_cv_cert.ber", ios::binary);
//cert_file << der; // this is bad !!!
  cert_file.write((char*)der.begin(), der.size());
  cert_file.close();

  Botan::EAC1_1_CVC cert_in("checks/temp/my_cv_cert.ber");
  BOOST_CHECK(cert == cert_in);
// encoding it again while it has no dp
  Botan::SecureVector<Botan::byte> der2(cert_in.BER_encode());
  ofstream cert_file2("checks/temp/my_cv_cert2.ber", ios::binary);
  cert_file2.write((char*)der2.begin(), der2.size());
  cert_file2.close();
// read both and compare them
  ifstream cert_1_in("checks/temp/my_cv_cert.ber");
  ifstream cert_2_in("checks/temp/my_cv_cert2.ber");
  Botan::SecureVector<Botan::byte> sv1;
  Botan::SecureVector<Botan::byte> sv2;
  if (!cert_1_in || !cert_2_in)
    {
      BOOST_CHECK_MESSAGE(false, "could not read certificate files");
    }
  while (!cert_1_in.eof())
    {
      char now;

      cert_1_in.read(&now, 1);
      sv1.append(now);
    }
  while (!cert_2_in.eof())
    {
      char now;
      cert_2_in.read(&now, 1);
      sv2.append(now);
    }
  BOOST_CHECK(sv1.size() > 10);
  BOOST_CHECK_MESSAGE(sv1 == sv2, "reencoded file of cert without domain parameters is different from original");

//cout << "reading cert again\n";
  BOOST_CHECK(cert_in.get_car().value() == "my_opt_car");
  BOOST_CHECK(cert_in.get_chr().value() == "my_opt_car");
  BOOST_CHECK(cert_in.get_ced().as_string() == "20100727");
  BOOST_CHECK(cert_in.get_ced().readable_string() == "2010/07/27 ");

  bool ill_date_exc = false;
  try
    {
      Botan::ASN1_Ced("1999 01 01");
    }
  catch (...)
    {
      ill_date_exc = true;
    }
  BOOST_CHECK(ill_date_exc);

  bool ill_date_exc2 = false;
  try
    {
      Botan::ASN1_Ced("2100 01 01");
    }
  catch (...)
    {
      ill_date_exc2 = true;
    }
  BOOST_CHECK(ill_date_exc2);
//cout << "readable = '" << cert_in.get_ced().readable_string() << "'\n";
  auto_ptr<Botan::Public_Key> p_pk = cert_in.subject_public_key();
//auto_ptr<Botan::ECDSA_PublicKey> ecdsa_pk = dynamic_cast<auto_ptr<Botan::ECDSA_PublicKey> >(p_pk);
  Botan::ECDSA_PublicKey* p_ecdsa_pk = dynamic_cast<Botan::ECDSA_PublicKey*>(p_pk.get());
// let´s see if encoding is truely implicitca, because this is what the key should have
// been set to when decoding (see above)(because it has no domain params):
//cout << "encoding = " << p_ecdsa_pk->get_parameter_encoding() << endl;
  BOOST_CHECK(p_ecdsa_pk->get_parameter_encoding() == Botan::ENC_IMPLICITCA);
  bool exc = false;
  try
    {
      cout << "order = " << p_ecdsa_pk->get_domain_parameters().get_order() << endl;
    }
  catch (Botan::Invalid_State)
    {
      exc = true;
    }
  BOOST_CHECK(exc);
// set them and try again
  //cert_in.set_domain_parameters(dom_pars);
  auto_ptr<Botan::Public_Key> p_pk2 = cert_in.subject_public_key();
  Botan::ECDSA_PublicKey* p_ecdsa_pk2 = dynamic_cast<Botan::ECDSA_PublicKey*>(p_pk2.get());
  p_ecdsa_pk2->set_domain_parameters(dom_pars);
  BOOST_CHECK(p_ecdsa_pk2->get_domain_parameters().get_order() == dom_pars.get_order());
  bool ver_ec = cert_in.check_signature(*p_pk2);
  BOOST_CHECK_MESSAGE(ver_ec, "could not positively verify correct selfsigned cvc certificate");
}

BOOST_AUTO_TEST_CASE( test_enc_gen_req)
{
  cout << "." << flush;
  Botan::LibraryInitializer init;
  Botan::EAC1_1_CVC_Options opts;

//opts.cpi = 0;
  opts.chr = Botan::ASN1_Chr("my_opt_chr");
  opts.hash_alg = "SHA-1";

// creating a non sense selfsigned cert w/o dom pars
  Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.132.0.8"));
  Botan::ECDSA_PrivateKey key(dom_pars);
  key.set_parameter_encoding(Botan::ENC_IMPLICITCA);
  Botan::EAC1_1_Req req = Botan::CVC_EAC::create_cvc_req(key, opts.chr, opts.hash_alg);
  Botan::SecureVector<Botan::byte> der(req.BER_encode());
  ofstream req_file("checks/temp/my_cv_req.ber", ios::binary);
  req_file.write((char*)der.begin(), der.size());
  req_file.close();

// read and check signature...
  Botan::EAC1_1_Req req_in("checks/temp/my_cv_req.ber");
  //req_in.set_domain_parameters(dom_pars);
  auto_ptr<Botan::Public_Key> p_pk = req_in.subject_public_key();
  Botan::ECDSA_PublicKey* p_ecdsa_pk = dynamic_cast<Botan::ECDSA_PublicKey*>(p_pk.get());
  p_ecdsa_pk->set_domain_parameters(dom_pars);
  BOOST_CHECK(p_ecdsa_pk->get_domain_parameters().get_order() == dom_pars.get_order());
  bool ver_ec = req_in.check_signature(*p_pk);
  BOOST_CHECK_MESSAGE(ver_ec, "could not positively verify correct selfsigned (created by myself) cvc request");
}

BOOST_AUTO_TEST_CASE(test_cvc_req_ext)
{
  cout << "." << flush;
  Botan::LibraryInitializer init;
  Botan::EAC1_1_Req req_in("checks/testdata/DE1_flen_chars_cvcRequest_ECDSA.der");
  Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.36.3.3.2.8.1.1.5")); // "german curve"
  //req_in.set_domain_parameters(dom_pars);
  auto_ptr<Botan::Public_Key> p_pk = req_in.subject_public_key();
  Botan::ECDSA_PublicKey* p_ecdsa_pk = dynamic_cast<Botan::ECDSA_PublicKey*>(p_pk.get());
  p_ecdsa_pk->set_domain_parameters(dom_pars);
  BOOST_CHECK(p_ecdsa_pk->get_domain_parameters().get_order() == dom_pars.get_order());
  bool ver_ec = req_in.check_signature(*p_pk);
  BOOST_CHECK_MESSAGE(ver_ec, "could not positively verify correct selfsigned (external testdata) cvc request");
}

BOOST_AUTO_TEST_CASE(test_cvc_ado_ext)
{
  cout << "." << flush;
  Botan::LibraryInitializer init;
  Botan::EAC1_1_ADO req_in("checks/testdata/ado.cvcreq");
  Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.36.3.3.2.8.1.1.5")); // "german curve"
//cout << "car = " << req_in.get_car().value() << endl;
//req_in.set_domain_parameters(dom_pars);
}

BOOST_AUTO_TEST_CASE(test_cvc_ado_creation)
{
  cout << "." << flush;
  Botan::LibraryInitializer init;
  Botan::EAC1_1_CVC_Options opts;
//opts.cpi = 0;
  opts.chr = Botan::ASN1_Chr("my_opt_chr");
  opts.hash_alg = "SHA-256";

// creating a non sense selfsigned cert w/o dom pars
  Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.36.3.3.2.8.1.1.11"));
//cout << "mod = " << hex << dom_pars.get_curve().get_p() << endl;
  Botan::ECDSA_PrivateKey req_key(dom_pars);
  req_key.set_parameter_encoding(Botan::ENC_IMPLICITCA);
//EAC1_1_Req req = Botan::CVC_EAC::create_cvc_req(req_key, opts);
  Botan::EAC1_1_Req req = Botan::CVC_EAC::create_cvc_req(req_key, opts.chr, opts.hash_alg);
  Botan::SecureVector<Botan::byte> der(req.BER_encode());
  ofstream req_file("checks/temp/my_cv_req.ber", ios::binary);
  req_file.write((char*)der.begin(), der.size());
  req_file.close();

// create an ado with that req
  Botan::ECDSA_PrivateKey ado_key(dom_pars);
  Botan::EAC1_1_CVC_Options ado_opts;
  ado_opts.car = Botan::ASN1_Car("my_ado_car");
  ado_opts.hash_alg = "SHA-256"; // must be equal to req´s hash alg, because ado takes his sig_algo from it´s request

//Botan::EAC1_1_ADO ado = Botan::CVC_EAC::create_ado_req(ado_key, req, ado_opts);
  Botan::EAC1_1_ADO ado = Botan::CVC_EAC::create_ado_req(ado_key, req, ado_opts.car);
  BOOST_CHECK_MESSAGE(ado.check_signature(ado_key), "failure of ado verification after creation");

  ofstream ado_file("checks/temp/ado", ios::binary);
  Botan::SecureVector<Botan::byte> ado_der(ado.BER_encode());
  ado_file.write((char*)ado_der.begin(), ado_der.size());
  ado_file.close();
// read it again and check the signature
  Botan::EAC1_1_ADO ado2("checks/temp/ado");
  BOOST_CHECK(ado == ado2);
//Botan::ECDSA_PublicKey* p_ado_pk = dynamic_cast<Botan::ECDSA_PublicKey*>(&ado_key);
//bool ver = ado2.check_signature(*p_ado_pk);
  bool ver = ado2.check_signature(ado_key);
  BOOST_CHECK_MESSAGE(ver, "failure of ado verification after reloading");
}

BOOST_AUTO_TEST_CASE(test_cvc_ado_comparison)
{
  cout << "." << flush;
  Botan::LibraryInitializer init;
  Botan::EAC1_1_CVC_Options opts;
//opts.cpi = 0;
  opts.chr = Botan::ASN1_Chr("my_opt_chr");
  opts.hash_alg = "SHA-224";

// creating a non sense selfsigned cert w/o dom pars
  Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.36.3.3.2.8.1.1.11"));
  Botan::ECDSA_PrivateKey req_key(dom_pars);
  req_key.set_parameter_encoding(Botan::ENC_IMPLICITCA);
//Botan::EAC1_1_Req req = CVC_EAC::create_cvc_req(req_key, opts);
  Botan::EAC1_1_Req req = Botan::CVC_EAC::create_cvc_req(req_key, opts.chr, opts.hash_alg);


// create an ado with that req
  Botan::ECDSA_PrivateKey ado_key(dom_pars);
  Botan::EAC1_1_CVC_Options ado_opts;
  ado_opts.car = Botan::ASN1_Car("my_ado_car1");
  ado_opts.hash_alg = "SHA-224"; // must be equal to req´s hash alg, because ado takes his sig_algo from it´s request
//Botan::EAC1_1_ADO ado = Botan::CVC_EAC::create_ado_req(ado_key, req, ado_opts);
  Botan::EAC1_1_ADO ado = Botan::CVC_EAC::create_ado_req(ado_key, req, ado_opts.car);
  BOOST_CHECK_MESSAGE(ado.check_signature(ado_key), "failure of ado verification after creation");
// make a second one for comparison
  Botan::EAC1_1_CVC_Options opts2;
//opts2.cpi = 0;
  opts2.chr = Botan::ASN1_Chr("my_opt_chr");
  opts2.hash_alg = "SHA-1"; // this is the only difference
  Botan::ECDSA_PrivateKey req_key2(dom_pars);
  req_key.set_parameter_encoding(Botan::ENC_IMPLICITCA);
//Botan::EAC1_1_Req req2 = Botan::CVC_EAC::create_cvc_req(req_key2, opts2);
  Botan::EAC1_1_Req req2 = Botan::CVC_EAC::create_cvc_req(req_key2, opts2.chr, opts2.hash_alg);
  Botan::ECDSA_PrivateKey ado_key2(dom_pars);
  Botan::EAC1_1_CVC_Options ado_opts2;
  ado_opts2.car = Botan::ASN1_Car("my_ado_car1");
  ado_opts2.hash_alg = "SHA-1"; // must be equal to req´s hash alg, because ado takes his sig_algo from it´s request

  Botan::EAC1_1_ADO ado2 = Botan::CVC_EAC::create_ado_req(ado_key2, req2, ado_opts2.car);
  BOOST_CHECK_MESSAGE(ado2.check_signature(ado_key2), "failure of ado verification after creation");

  BOOST_CHECK_MESSAGE(ado != ado2, "ado´s found to be equal where they aren´t");
//     ofstream ado_file("checks/temp/ado");
//     Botan::SecureVector<Botan::byte> ado_der(ado.BER_encode());
//     ado_file.write((char*)ado_der.begin(), ado_der.size());
//     ado_file.close();
// read it again and check the signature

//    Botan::EAC1_1_ADO ado2("checks/temp/ado");
//    Botan::ECDSA_PublicKey* p_ado_pk = dynamic_cast<Botan::ECDSA_PublicKey*>(&ado_key);
//    //bool ver = ado2.check_signature(*p_ado_pk);
//    bool ver = ado2.check_signature(ado_key);
//    BOOST_CHECK_MESSAGE(ver, "failure of ado verification after reloading");
}

BOOST_AUTO_TEST_CASE(test_eac_time)
{
  cout << "." << flush;
  Botan::LibraryInitializer init;
  const Botan::u64bit current_time = Botan::system_time();
  Botan::EAC_Time time(current_time);
//     cout << "time as string = " << time.as_string() << endl;
  Botan::EAC_Time sooner("", Botan::ASN1_Tag(99));
//Botan::X509_Time sooner("", ASN1_Tag(99));
  sooner.set_to("2007 12 12");
//     cout << "sooner as string = " << sooner.as_string() << endl;
  Botan::EAC_Time later("2007 12 13");
//Botan::X509_Time later("2007 12 13");
//     cout << "later as string = " << later.as_string() << endl;
  BOOST_CHECK(sooner <= later);
  BOOST_CHECK(sooner == sooner);

  Botan::ASN1_Cex my_cex("2007 08 01");
  my_cex.add_months(12);
  BOOST_CHECK(my_cex.get_year() == 2008);
  BOOST_CHECK_MESSAGE(my_cex.get_month() == 8, "shoult be 8, was " << my_cex.get_month());

  my_cex.add_months(4);
  BOOST_CHECK(my_cex.get_year() == 2008);
  BOOST_CHECK(my_cex.get_month() == 12);

  my_cex.add_months(4);
  BOOST_CHECK(my_cex.get_year() == 2009);
  BOOST_CHECK(my_cex.get_month() == 4);

  my_cex.add_months(41);
  BOOST_CHECK(my_cex.get_year() == 2012);
  BOOST_CHECK(my_cex.get_month() == 9);



}

BOOST_AUTO_TEST_CASE(test_ver_cvca)
{
  cout << "." << flush;
  Botan::LibraryInitializer init;
  Botan::EAC1_1_CVC req_in("checks/testdata/cvca01.cv.crt");

//auto_ptr<Botan::ECDSA_PublicKey> ecdsa_pk = dynamic_cast<auto_ptr<Botan::ECDSA_PublicKey> >(p_pk);
//Botan::ECDSA_PublicKey* p_ecdsa_pk = dynamic_cast<Botan::ECDSA_PublicKey*>(p_pk.get());
  bool exc = false;

  auto_ptr<Botan::Public_Key> p_pk2 = req_in.subject_public_key();
  Botan::ECDSA_PublicKey* p_ecdsa_pk2 = dynamic_cast<Botan::ECDSA_PublicKey*>(p_pk2.get());
  bool ver_ec = req_in.check_signature(*p_pk2);
  BOOST_CHECK_MESSAGE(ver_ec, "could not positively verify correct selfsigned cvca certificate");

  try
    {
      p_ecdsa_pk2->get_domain_parameters().get_order();
    }
  catch (Botan::Invalid_State)
    {
      exc = true;
    }
  BOOST_CHECK(!exc);
}

BOOST_AUTO_TEST_CASE(test_copy_and_assignment)
{
  cout << "." << flush;
  Botan::LibraryInitializer init;
  Botan::EAC1_1_CVC cert_in("checks/testdata/cvca01.cv.crt");
  Botan::EAC1_1_CVC cert_cp(cert_in);
  Botan::EAC1_1_CVC cert_ass = cert_in;
  BOOST_CHECK(cert_in == cert_cp);
  BOOST_CHECK(cert_in == cert_ass);

  Botan::EAC1_1_ADO ado_in("checks/testdata/ado.cvcreq");
//EC_Domain_Params dom_pars(get_EC_Dom_Pars_by_oid("1.3.36.3.3.2.8.1.1.5")); // "german curve"
  Botan::EAC1_1_ADO ado_cp(ado_in);
  Botan::EAC1_1_ADO ado_ass = ado_in;
  BOOST_CHECK(ado_in == ado_cp);
  BOOST_CHECK(ado_in == ado_ass);

  Botan::EAC1_1_Req req_in("checks/testdata/DE1_flen_chars_cvcRequest_ECDSA.der");
//EC_Domain_Params dom_pars(get_EC_Dom_Pars_by_oid("1.3.36.3.3.2.8.1.1.5")); // "german curve"
  Botan::EAC1_1_Req req_cp(req_in);
  Botan::EAC1_1_Req req_ass = req_in;
  BOOST_CHECK(req_in == req_cp);
  BOOST_CHECK(req_in == req_ass);
}

BOOST_AUTO_TEST_CASE(test_eac_str_illegal_values)
{
  cout << "." << flush;
  Botan::LibraryInitializer init;
  bool exc = false;
  try
    {
      Botan::EAC1_1_CVC("checks/testdata/cvca_illegal_chars.cv.crt");

    }
  catch (Botan::Decoding_Error)
    {
      exc = true;
    }
  BOOST_CHECK(exc);

  bool exc2 = false;
  try
    {
      Botan::EAC1_1_CVC("checks/testdata/cvca_illegal_chars2.cv.crt");

    }
  catch (Botan::Decoding_Error)
    {
      exc2 = true;
    }
  BOOST_CHECK(exc2);
}

BOOST_AUTO_TEST_CASE(test_tmp_eac_str_enc)
{
  cout << "." << flush;
  Botan::LibraryInitializer init;
  bool exc = false;
  try
    {
      Botan::ASN1_Car("abc!+-µ\n");
    }
  catch (Botan::Invalid_Argument)
    {
      exc = true;
    }
  BOOST_CHECK(exc);
//     string val = car.iso_8859();
//     cout << "car 8859 = " << val << endl;
//     cout << hex <<(unsigned char)val[1] << endl;


}

BOOST_AUTO_TEST_CASE(test_cvc_chain)
{
  cout << "." << flush;
  Botan::LibraryInitializer init;
  Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.36.3.3.2.8.1.1.5")); // "german curve"
  Botan::ECDSA_PrivateKey cvca_privk(dom_pars);
  string hash("SHA-224");
  Botan::ASN1_Car car("DECVCA00001");
  Botan::EAC1_1_CVC cvca_cert = Botan::DE_EAC::create_cvca(cvca_privk, hash, car, true, true);
  ofstream cvca_file("checks/temp/cvc_chain_cvca.cer", ios::binary);
  Botan::SecureVector<Botan::byte> cvca_sv = cvca_cert.BER_encode();
  cvca_file.write((char*)cvca_sv.begin(), cvca_sv.size());
  cvca_file.close();

  Botan::ECDSA_PrivateKey cvca_privk2(dom_pars);
  Botan::ASN1_Car car2("DECVCA00002");
  Botan::EAC1_1_CVC cvca_cert2 = Botan::DE_EAC::create_cvca(cvca_privk2, hash, car2, true, true);
  Botan::EAC1_1_CVC link12 = Botan::DE_EAC::link_cvca(cvca_cert, cvca_privk, cvca_cert2);
  Botan::SecureVector<Botan::byte> link12_sv = link12.BER_encode();
  ofstream link12_file("checks/temp/cvc_chain_link12.cer", ios::binary);
  link12_file.write((char*)link12_sv.begin(), link12_sv.size());
  link12_file.close();

    // verify the link
    BOOST_CHECK(link12.check_signature(cvca_privk));
    Botan::EAC1_1_CVC link12_reloaded("checks/temp/cvc_chain_link12.cer");
    Botan::EAC1_1_CVC cvca1_reloaded("checks/temp/cvc_chain_cvca.cer");
    auto_ptr<Botan::Public_Key> cvca1_rel_pk = cvca1_reloaded.subject_public_key();
    BOOST_CHECK(link12_reloaded.check_signature(*cvca1_rel_pk));

  // create first round dvca-req
  Botan::ECDSA_PrivateKey dvca_priv_key(dom_pars);
  Botan::EAC1_1_Req dvca_req = Botan::DE_EAC::create_cvc_req(dvca_priv_key, Botan::ASN1_Chr("DEDVCAEPASS"), hash);
  ofstream dvca_file("checks/temp/cvc_chain_dvca_req.cer", ios::binary);
  Botan::SecureVector<Botan::byte> dvca_sv = dvca_req.BER_encode();
  dvca_file.write((char*)dvca_sv.begin(), dvca_sv.size());
  dvca_file.close();

  // sign the dvca_request
  Botan::EAC1_1_CVC dvca_cert1 = Botan::DE_EAC::sign_request(cvca_cert, cvca_privk, dvca_req, 1, 5, true);
  BOOST_CHECK(dvca_cert1.get_car().iso_8859() == "DECVCA00001");
  BOOST_CHECK(dvca_cert1.get_chr().iso_8859() == "DEDVCAEPASS00001");
  helper_write_file(dvca_cert1, "checks/temp/cvc_chain_dvca_cert1.cer");

  // make a second round dvca ado request
  Botan::ECDSA_PrivateKey dvca_priv_key2(dom_pars);
  Botan::EAC1_1_Req dvca_req2 = Botan::DE_EAC::create_cvc_req(dvca_priv_key2, Botan::ASN1_Chr("DEDVCAEPASS"), hash);
  ofstream dvca_file2("checks/temp/cvc_chain_dvca_req2.cer", ios::binary);
  Botan::SecureVector<Botan::byte> dvca_sv2 = dvca_req2.BER_encode();
  dvca_file2.write((char*)dvca_sv2.begin(), dvca_sv2.size());
  dvca_file2.close();
  Botan::EAC1_1_ADO dvca_ado2 = Botan::CVC_EAC::create_ado_req(dvca_priv_key, dvca_req2,
                                Botan::ASN1_Car(dvca_cert1.get_chr().iso_8859()));
  helper_write_file(dvca_ado2, "checks/temp/cvc_chain_dvca_ado2.cer");

  // verify the ado and sign the request too

  auto_ptr<Botan::Public_Key> ap_pk = dvca_cert1.subject_public_key();
  Botan::ECDSA_PublicKey* cert_pk = dynamic_cast<Botan::ECDSA_PublicKey*>(ap_pk.get());

  cert_pk->set_domain_parameters(dom_pars);
  //    cout << "dvca_cert.public_point.size() = " << ec::EC2OSP(cert_pk->get_public_point(), ec::PointGFp::COMPRESSED).size() << endl;
  Botan::EAC1_1_CVC dvca_cert1_reread("checks/temp/cvc_chain_cvca.cer");
  BOOST_CHECK(dvca_ado2.check_signature(*cert_pk));

  BOOST_CHECK(dvca_ado2.check_signature(dvca_priv_key)); // must also work

  Botan::EAC1_1_Req dvca_req2b = dvca_ado2.get_request();
  helper_write_file(dvca_req2b, "checks/temp/cvc_chain_dvca_req2b.cer");
  BOOST_CHECK(helper_files_equal("checks/temp/cvc_chain_dvca_req2b.cer", "checks/temp/cvc_chain_dvca_req2.cer"));
  Botan::EAC1_1_CVC dvca_cert2 = Botan::DE_EAC::sign_request(cvca_cert, cvca_privk, dvca_req2b, 2, 5, true);
  BOOST_CHECK(dvca_cert2.get_car().iso_8859() == "DECVCA00001");
  BOOST_CHECK_MESSAGE(dvca_cert2.get_chr().iso_8859() == "DEDVCAEPASS00002",
                      "chr = " << dvca_cert2.get_chr().iso_8859());

  // make a first round IS request
  Botan::ECDSA_PrivateKey is_priv_key(dom_pars);
  Botan::EAC1_1_Req is_req = Botan::DE_EAC::create_cvc_req(is_priv_key, Botan::ASN1_Chr("DEIS"), hash);
  helper_write_file(is_req, "checks/temp/cvc_chain_is_req.cer");

  // sign the IS request
  //dvca_cert1.set_domain_parameters(dom_pars);
  Botan::EAC1_1_CVC is_cert1 = Botan::DE_EAC::sign_request(dvca_cert1, dvca_priv_key, is_req, 1, 5, true);
  BOOST_CHECK_MESSAGE(is_cert1.get_car().iso_8859() == "DEDVCAEPASS00001", "car = " << is_cert1.get_car().iso_8859());
  BOOST_CHECK(is_cert1.get_chr().iso_8859() == "DEIS00001");
  helper_write_file(is_cert1, "checks/temp/cvc_chain_is_cert.cer");

  // verify the signature of the certificate
  BOOST_CHECK(is_cert1.check_signature(dvca_priv_key));
}
