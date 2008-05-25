/******************************************************
* eckaeg tests                                        *
*                                                     *
* (C) 2007 Manuel Hartl                               *
*          hartl@flexsecure.de                        *
******************************************************/

#include <iostream>
#include <fstream>

#include <botan/dh.h>
#include <botan/ec.h>
#include <botan/x509self.h>
#include <botan/der_enc.h>

#include <botan/math/ec/point_gfp.h>
#include <botan/math/ec/curve_gfp.h>
#include <botan/math/gf/gfp_element.h>

using namespace Botan::math::gf;

BOOST_AUTO_TEST_CASE(test_eckaeg_normal_derivation)
{
	cout << "." << flush;
    // init the lib
    Botan::InitializerOptions init_options("");
    Botan::LibraryInitializer init(init_options);

    //
    /*
    string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
    string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
    string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
    string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
    ::Botan::SecureVector<byte> sv_p_secp = decode_hex(p_secp);
    ::Botan::SecureVector<byte> sv_a_secp = decode_hex(a_secp);
    ::Botan::SecureVector<byte> sv_b_secp = decode_hex(b_secp);
    ::Botan::SecureVector<byte> sv_G_secp_comp = decode_hex(G_secp_comp);
    BigInt bi_p_secp = BigInt::decode(sv_p_secp.begin(), sv_p_secp.size());
    BigInt bi_a_secp = BigInt::decode(sv_a_secp.begin(), sv_a_secp.size());
    BigInt bi_b_secp = BigInt::decode(sv_b_secp.begin(), sv_b_secp.size());
    CurveGFp secp160r1(GFpElement(bi_p_secp,bi_a_secp), GFpElement(bi_p_secp, bi_b_secp), bi_p_secp);
    */

    string g_secp("024a96b5688ef573284664698968c38bb913cbfc82");
    Botan::SecureVector<Botan::byte> sv_g_secp = decode_hex(g_secp);
    BigInt bi_p_secp("0xffffffffffffffffffffffffffffffff7fffffff");
    BigInt bi_a_secp("0xffffffffffffffffffffffffffffffff7ffffffc");
    BigInt bi_b_secp("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
    BigInt order = BigInt("0x0100000000000000000001f4c8f927aed3ca752257");
    CurveGFp curve(gf::GFpElement(bi_p_secp,bi_a_secp), gf::GFpElement(bi_p_secp, bi_b_secp), bi_p_secp);
    BigInt cofactor = BigInt(1);
    PointGFp p_G = OS2ECP ( sv_g_secp, curve );
    Botan::EC_Domain_Params dom_pars = Botan::EC_Domain_Params(curve, p_G, order, cofactor);

    /**
    * begin ECKAEG
    */
    // alices key (a key constructed by domain parameters IS an ephimeral key!)
    Botan::ECKAEG_PrivateKey private_a(dom_pars);
    Botan::ECKAEG_PublicKey public_a = private_a; // Bob gets this

    // Bob creates a key with a matching group
    Botan::ECKAEG_PrivateKey private_b(dom_pars); //public_a.getCurve()

    // Bob sends the key back to Alice
    Botan::ECKAEG_PublicKey public_b = private_b; // Alice gets this

    // Both of them create a key using their private key and the other's
    // public key
    Botan::SymmetricKey alice_key = private_a.derive_key(public_b);
    Botan::SymmetricKey bob_key = private_b.derive_key(public_a);

    BOOST_CHECK_MESSAGE(alice_key == bob_key, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
    //cout << "key: " << alice_key.as_string() << endl;
    /*
    if(alice_key == bob_key)
    {
    std::cout << "The two keys matched, everything worked\n";
    std::cout << "bit length " << alice_key.length() << endl;
    std::cout << "The shared key was: " << alice_key.as_string() << "\n";
    }

    else
    {
    std::cout << "The two keys didn't match!\n";
    std::cout << "Alice's key was: " << alice_key.as_string() << "\n";
    std::cout << "Bob's key was: " << bob_key.as_string() << "\n";
    }
    */
    // Now Alice and Bob hash the key and use it for something
}

BOOST_AUTO_TEST_CASE(test_eckaeg_some_dp)
{
    Botan::InitializerOptions init_options("");
    Botan::LibraryInitializer init(init_options);

    vector<string> oids;
    oids.push_back("1.2.840.10045.3.1.7");
    oids.push_back("1.3.132.0.8");
    oids.push_back("1.2.840.10045.3.1.1");
    for(Botan::u32bit i = 0; i< oids.size(); i++)
    {
		cout << "." << flush;
        Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid(oids[i]));
        Botan::ECKAEG_PrivateKey private_a(dom_pars);
        Botan::ECKAEG_PublicKey public_a = private_a;
        /*auto_ptr<Botan::X509_Encoder> x509_key_enc = public_a.x509_encoder();
        Botan::MemoryVector<Botan::byte> enc_key_a = Botan::DER_Encoder()
            .start_cons(Botan::SEQUENCE)
            .encode(x509_key_enc->alg_id())
            .encode(x509_key_enc->key_bits(), Botan::BIT_STRING)
            .end_cons()
            .get_contents();*/

        Botan::ECKAEG_PrivateKey private_b(dom_pars);
        Botan::ECKAEG_PublicKey public_b = private_b;
        // to test the equivalence, we
        // use the direct derivation method here

        Botan::SymmetricKey alice_key = private_a.derive_key(public_b);

        //cout << "encoded key = " << hex_encode(enc_key_a.begin(), enc_key_a.size()) << endl;

        Botan::SymmetricKey bob_key = private_b.derive_key(public_a);
        BOOST_CHECK_MESSAGE(alice_key == bob_key, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
        //cout << "key: " << alice_key.as_string() << endl;
    }

}

/*BOOST_AUTO_TEST_CASE(test_eckaeg_der_derivation)
{
    Botan::InitializerOptions init_options("");
    Botan::LibraryInitializer init(init_options);

    vector<string> oids;
    oids.push_back("1.2.840.10045.3.1.7");
    oids.push_back("1.3.132.0.8");
    oids.push_back("1.2.840.10045.3.1.1");
    for(Botan::u32bit i = 0; i< oids.size(); i++)
    {
        Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid(oids[i]));
        Botan::ECKAEG_PrivateKey private_a(dom_pars);
        Botan::ECKAEG_PublicKey public_a = private_a;
        Botan::ECKAEG_PrivateKey private_b(dom_pars);
        Botan::ECKAEG_PublicKey public_b = private_b;
        Botan::MemoryVector<Botan::byte> key_der_a = private_a.public_value();
        Botan::MemoryVector<Botan::byte> key_der_b = private_b.public_value();
        Botan::SymmetricKey alice_key = private_a.derive_key(key_der_b.begin(), key_der_b.size());
        Botan::SymmetricKey bob_key = private_b.derive_key(key_der_a.begin(), key_der_a.size());
        BOOST_CHECK_MESSAGE(alice_key == bob_key, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
        //cout << "key: " << alice_key.as_string() << endl;
    }
}*/

/**
* The following test tests the copy ctors and and copy-assignment operators
*/
BOOST_AUTO_TEST_CASE(test_eckaeg_cp_ctor_as_op)
{
	cout << "." << flush;
    // init the lib
    Botan::InitializerOptions init_options("");
    Botan::LibraryInitializer init(init_options);

    string g_secp("024a96b5688ef573284664698968c38bb913cbfc82");
    Botan::SecureVector<Botan::byte> sv_g_secp = decode_hex(g_secp);
    BigInt bi_p_secp("0xffffffffffffffffffffffffffffffff7fffffff");
    BigInt bi_a_secp("0xffffffffffffffffffffffffffffffff7ffffffc");
    BigInt bi_b_secp("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
    BigInt order = BigInt("0x0100000000000000000001f4c8f927aed3ca752257");
    CurveGFp curve(gf::GFpElement(bi_p_secp,bi_a_secp), gf::GFpElement(bi_p_secp, bi_b_secp), bi_p_secp);
    BigInt cofactor = BigInt(1);
    PointGFp p_G = OS2ECP ( sv_g_secp, curve );
    Botan::EC_Domain_Params dom_pars = Botan::EC_Domain_Params(curve, p_G, order, cofactor);

    /**
    * begin ECKAEG
    */
    // alices key (a key constructed by domain parameters IS an ephimeral key!)
    Botan::ECKAEG_PrivateKey private_a(dom_pars);
    Botan::ECKAEG_PrivateKey private_a2(private_a);
    Botan::ECKAEG_PrivateKey private_a3;
    private_a3 = private_a2;

    Botan::DH_PrivateKey dh_pr_empty;
    Botan::DH_PublicKey dh_pub_empty;

    Botan::ECKAEG_PublicKey public_a = private_a; // Bob gets this
    Botan::ECKAEG_PublicKey public_a2(public_a);
    Botan::ECKAEG_PublicKey public_a3;
    public_a3 = public_a;
    // Bob creates a key with a matching group
    Botan::ECKAEG_PrivateKey private_b(dom_pars); //public_a.getCurve()

    // Bob sends the key back to Alice
    Botan::ECKAEG_PublicKey public_b = private_b; // Alice gets this

    // Both of them create a key using their private key and the other's
    // public key
    Botan::SymmetricKey alice_key = private_a.derive_key(public_b);
    Botan::SymmetricKey alice_key_2 = private_a2.derive_key(public_b);
    Botan::SymmetricKey alice_key_3 = private_a3.derive_key(public_b);

    Botan::SymmetricKey bob_key = private_b.derive_key(public_a);
    Botan::SymmetricKey bob_key_2 = private_b.derive_key(public_a2);
    Botan::SymmetricKey bob_key_3 = private_b.derive_key(public_a3);

    BOOST_CHECK_MESSAGE(alice_key == bob_key, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
    BOOST_CHECK_MESSAGE(alice_key_2 == bob_key_2, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
    BOOST_CHECK_MESSAGE(alice_key_3 == bob_key_3, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
    BOOST_CHECK_MESSAGE(alice_key == bob_key_2, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
    BOOST_CHECK_MESSAGE(alice_key_2 == bob_key_3, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
}

/**
* The following test tests whether ECKAEG keys exhibit correct behaviour when it is
* attempted to use them in an uninitialized state
*/
BOOST_AUTO_TEST_CASE(test_non_init_eckaeg_keys)
{
	cout << "." << flush;
    // init the lib
    Botan::InitializerOptions init_options("");
    Botan::LibraryInitializer init(init_options);

    // set up dom pars
    string g_secp("024a96b5688ef573284664698968c38bb913cbfc82");
    Botan::SecureVector<Botan::byte> sv_g_secp = decode_hex(g_secp);
    BigInt bi_p_secp("0xffffffffffffffffffffffffffffffff7fffffff");
    BigInt bi_a_secp("0xffffffffffffffffffffffffffffffff7ffffffc");
    BigInt bi_b_secp("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
    BigInt order = BigInt("0x0100000000000000000001f4c8f927aed3ca752257");
    CurveGFp curve(gf::GFpElement(bi_p_secp,bi_a_secp), gf::GFpElement(bi_p_secp, bi_b_secp), bi_p_secp);
    BigInt cofactor = BigInt(1);
    PointGFp p_G = OS2ECP ( sv_g_secp, curve );
    Botan::EC_Domain_Params dom_pars = Botan::EC_Domain_Params(curve, p_G, order, cofactor);

    // alices key (a key constructed by domain parameters IS an ephimeral key!)
    Botan::ECKAEG_PrivateKey private_a(dom_pars);
    Botan::ECKAEG_PrivateKey private_b(dom_pars);

    Botan::ECKAEG_PublicKey public_b;

    Botan::ECKAEG_PrivateKey private_empty;
    Botan::ECKAEG_PublicKey public_empty;
    bool exc1 = false;
    try {
        Botan::SymmetricKey void_key = private_empty.derive_key(public_b);
    }
    catch (Botan::Exception e) {
        exc1 = true;
    }
    BOOST_CHECK_MESSAGE(exc1, "there was no exception thrown when attempting to use an uninitialized ECKAEG key");

    bool exc2 = false;
    try {
        Botan::SymmetricKey void_key = private_a.derive_key(public_empty);
    }
    catch (Botan::Exception e) {
        exc2 = true;
    }
    BOOST_CHECK_MESSAGE(exc2, "there was no exception thrown when attempting to use an uninitialized ECKAEG key");
}
