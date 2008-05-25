//#include <botan/math/ec/point_gfp.h>
//#include <botan/math/ec/curve_gfp.h>
//#include <botan/math/gf/gfp_element.h>
//#include <botan/math/bigint.h>
//#include <botan/botan.h>
//#include <botan/math/mp_types.h>
//#include <botan/secmem.h>
//#include <botan/types.h>
//#include <botan/math/bigintfuncs.h>
//#include <botan/math/mp_types.h>
//#include <botan/types.h>
//#include <botan/base.h>
//#include <botan/secmem.h>
//#include <iosfwd>
//#include <botan/ec.h>
//#include <botan/ec_dompar.h>
//#include "common.h"
//#include <botan/x509cert.h>
//#include <botan/oids.h>
//#include <botan/look_pk.h>
//#include<botan/tr1_mem_includer.h>
////#include <tr1/memory>
//
//#include <botan/pubkey.h>
//#include <iostream>
//#include <iterator>
//#include <algorithm>
#include <botan/look_pk.h>
//#include <botan/x509self.h>
//#include <botan/rsa.h>
//#include <fstream>
//#include <vector>
//#include <sstream>

//using namespace Botan_types;
//using namespace Botan;
using namespace Botan;
//using namespace std;
//using namespace Botan::math;
//using namespace Botan::math::gf;
//using namespace Botan::math::ec;
using boost::unit_test::test_suite;

BOOST_AUTO_TEST_CASE(test_rsa_sign2)
{
	Botan::InitializerOptions init_options("");
	Botan::LibraryInitializer init(init_options);
	RSA_PrivateKey rsa_key(1024);

	std::auto_ptr<Botan::PK_Signer> rsa_sig = get_pk_signer(rsa_key, "Raw");
    std::tr1::shared_ptr<Botan::PK_Signer> sp_rsa_sig(rsa_sig);
	Pipe pipe(create_shared_ptr<PK_Signer_Filter>(sp_rsa_sig));

	string message("123456789abcdeffedcba987654321");
	SecureVector<byte> sv_message = decode_hex(message);

	pipe.process_msg(message);
	SecureVector<byte> signature = pipe.read_all();



	SecureVector<byte> signature2 = sp_rsa_sig->sign_message(sv_message);

	cout << "signature vector: " << hex_encode(signature, signature.size()) << endl;
	cout << "signature vector2: " << hex_encode(signature2, signature.size()) << endl;
//	signature[signature.size()-1] += 0x01;

	std::auto_ptr<Botan::PK_Verifier> verifier = get_pk_verifier(rsa_key, "Raw");
	std::tr1::shared_ptr<Botan::PK_Verifier> sp_verifier(verifier);
	Pipe pipe2(create_shared_ptr<PK_Verifier_Filter>(sp_verifier, signature));
	pipe2.process_msg(message);
	SecureVector<byte> success2 = pipe2.read_all();


	bool success = sp_verifier->verify_message(sv_message, signature2);

	cout << hex_encode(success2, success2.size()) << endl;
	cout << success << endl;
}
BOOST_AUTO_TEST_CASE(test_rsa_sign)
{
	Botan::InitializerOptions init_options("");
	Botan::LibraryInitializer init(init_options);
	stringstream message("Ich will signiert werden!");
	RSA_PrivateKey rsa_key(1024);
	std::auto_ptr<Botan::PK_Signer> rsa_sig = get_pk_signer(rsa_key, "Raw");
    std::tr1::shared_ptr<Botan::PK_Signer> sp_rsa_sig(rsa_sig);
	Pipe pipe(create_shared_ptr<PK_Signer_Filter>(sp_rsa_sig));

 	// sign
	pipe.start_msg();
	message >> pipe;
	pipe.end_msg();

	SecureVector<byte> signature = pipe.read_all();
	cout << "signature vector: " << hex_encode(signature, signature.size()) << endl;

	// verify
	std::auto_ptr<Botan::PK_Verifier> verifier = get_pk_verifier(rsa_key, "Raw");
	std::tr1::shared_ptr<Botan::PK_Verifier> sp_verifier(verifier);
	Pipe pipe2(create_shared_ptr<PK_Verifier_Filter>(sp_verifier, signature));

	pipe2.start_msg();
	//message >> pipe2; // cannot work
	cout << message; // this gives "0"
	pipe2.end_msg();

	//check
	SecureVector<byte> ver_success = pipe2.read_all();
	cout << "result vector: " << hex_encode(ver_success, ver_success.size()) << endl;
}
