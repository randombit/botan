/******************************************************
* sha1prng tests                                      *
*                                                     *
* (C) 2007 Manuel Hartl                               *
*          hartl@flexsecure.de                        *
******************************************************/

#include <iostream>
#include <fstream>

#include <botan/sha1prng.h>

#ifdef NORANDPOOL
BOOST_AUTO_TEST_CASE(test_sha1prng_determ)
{
    // init the lib
    Botan::InitializerOptions init_options("");
    Botan::LibraryInitializer init(init_options);

    /**
    * init
    */
    Botan::RandomNumberGenerator* rn = (Botan::RandomNumberGenerator*) new Botan::SHA1PRNG;
    int seedlen=20;
    Botan::byte* seed = new Botan::byte[seedlen];
    for (int i=0;i<seedlen;i++)
    {
        seed[i]=0;
    }
    for (int i=0;i<300;i++)
    {
        rn->add_entropy(seed,seedlen);
    }
    delete[] seed;
    /**
    * work
    */
    int reslen = 20;
    Botan::byte* out = new Botan::byte[reslen];
    for (int i=0;i<reslen;i++)
    {
        out[i]=0;
    }

    for (int j=0;j<2;j++)
    {
		cout << "." << flush;
        rn->randomize(out,reslen);
        string comp;
        switch (j) 
        {
        case 0:
            comp="24D5D1ED739E0825BC6D9D44A7DD0D720454EAFA";
            break;
        case 1:
            comp="9568C4150579CDE12E8F24538EBC6E43E3ABEFE5";
            break;
        }
        Botan::SecureVector<Botan::byte> res = decode_hex(comp);
        BOOST_CHECK_MESSAGE(hex_encode(out,reslen)==hex_encode(res,res.size()),
            "result was: '" << hex_encode(out,reslen) << "' but should be: '" << hex_encode(res,res.size()) << "'");
    }
    delete[] out;
    delete rn;
}
#endif

#ifndef NORANDPOOL
BOOST_AUTO_TEST_CASE(test_sha1prng_non_determ)
{
    // init the lib
    Botan::InitializerOptions init_options("");
    Botan::LibraryInitializer init(init_options);

    /**
    * init
    */
    auto_ptr<Botan::RandomNumberGenerator> rn1((Botan::RandomNumberGenerator*) new Botan::SHA1PRNG);
    auto_ptr<Botan::RandomNumberGenerator> rn2((Botan::RandomNumberGenerator*) new Botan::SHA1PRNG);
    int seedlen=20;
    Botan::byte* seed = new Botan::byte[seedlen];
    for (int i=0;i<seedlen;i++)
    {
        seed[i]=i;
    }
    for (int i=0;i<600;i++)
    {
        rn1->add_entropy(seed,seedlen);
        rn2->add_entropy(seed,seedlen);
    }
    delete[] seed;

    /**
    * work
    */
    int reslen = 20;
    Botan::byte* out = new Botan::byte[reslen];
    for (int i=0;i<reslen;i++)
    {
        out[i]=0;
    }
    Botan::MemoryVector<Botan::byte> out_for_rn1;
    out_for_rn1.set(out, reslen);
    Botan::MemoryVector<Botan::byte> out_for_rn2;
    out_for_rn2.set(out, reslen);
    for (int j=0;j<2;j++)
    {
		cout << "." << flush;
        rn1->randomize(out_for_rn1,reslen);
        rn2->randomize(out_for_rn2,reslen);
        //assert(out_for_rn1 == out_for_rn2);
        //string comp;

        //Botan::SecureVector<Botan::byte> res = Botan::decode_hex(comp);
        BOOST_CHECK_MESSAGE(hex_encode(out_for_rn1.begin(),out_for_rn1.size())!=hex_encode(out_for_rn2.begin(),out_for_rn2.size() ), "result was deterministic");
    }

    delete[] out;
}
#endif

#ifndef NORANDPOOL
/**
* tests whether an exception is thrown in the case the rng is used to
* produce randomness without having added enough entropy before.
*/
BOOST_AUTO_TEST_CASE(test_sha1prng_not_enough_entropy)
{
	cout << "." << flush;
    // init the lib
    Botan::InitializerOptions init_options("");
    Botan::LibraryInitializer init(init_options);

    /**
    * init
    */
    Botan::RandomNumberGenerator* rn = new Botan::SHA1PRNG;
    int seedlen=20;
    Botan::byte* seed = new Botan::byte[seedlen];
    for (int i=0;i<seedlen;i++)
    {
        seed[i]=0; // this is not really adding entropy
    }
    for (int i=0;i<300;i++)
    {
        rn->add_entropy(seed,seedlen);
    }
    delete[] seed;

    /**
    * work
    */
    int reslen = 20;
    Botan::byte* out = new Botan::byte[reslen];
    for (int i=0;i<reslen;i++)
    {
        out[i]=0;
    }
    bool exc = false;
    try{
        rn->randomize(out,reslen); // supposed to throw
    } catch (exception e)
    {
        exc = true;
    }
    BOOST_CHECK(exc);
    delete[] out;
    delete rn;
}
#endif
