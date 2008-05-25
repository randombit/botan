/******************************************************
* dh tests                                            *
*                                                     *
* (C) 2007 Manuel Hartl                               *
*          hartl@flexsecure.de                        * 
******************************************************/

#include <iostream>
#include <fstream>

#include <botan/dh.h>

BOOST_AUTO_TEST_CASE(test_dh)
{
	cout << "." << flush;
    // init the lib
    Botan::InitializerOptions init_options("");
    Botan::LibraryInitializer init(init_options);

    // Alice creates a DH key and sends (the public part) to Bob
    Botan::DH_PrivateKey private_a(Botan::DL_Group("modp/ietf/1024"));
    Botan::DH_PublicKey public_a = private_a; // Bob gets this

    // Bob creates a key with a matching group
    Botan::DH_PrivateKey private_b(public_a.get_domain());

    // Bob sends the key back to Alice
    Botan::DH_PublicKey public_b = private_b; // Alice gets this

    // Both of them create a key using their private key and the other's
    // public key
    Botan::SymmetricKey alice_key = private_a.derive_key(public_b);
    Botan::SymmetricKey bob_key = private_b.derive_key(public_a);

    BOOST_CHECK_MESSAGE(alice_key == bob_key, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
    /*
    if(alice_key == bob_key)
    {
    std::cout << "The two keys matched, everything worked\n";
    std::cout << "The shared key was: " << alice_key.as_string() << "\n";
    }
    else
    {
    std::cout << "The two keys didn't match!\n";
    std::cout << "Alice's key was: " << alice_key.as_string() << "\n";
    std::cout << "Bob's key was: " << bob_key.as_string() << "\n";
    }

    // Now Alice and Bob hash the key and use it for something
    */
}
