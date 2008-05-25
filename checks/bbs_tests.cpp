/******************************************************
* blum blum shub tests                                *
*                                                     *
* (C) 2007 Manuel Hartl                               *
*          hartl@flexsecure.de                        *
******************************************************/

#include <iostream>
#include <fstream>

#include <botan/bbs.h>

#ifdef NORANDPOOL
BOOST_AUTO_TEST_CASE(test_bbs_determ)
{
    // init the lib
    Botan::InitializerOptions init_options("");
    Botan::LibraryInitializer init(init_options);

    /**
    * init
    */
    Botan::RandomNumberGenerator* rn = (Botan::RandomNumberGenerator*) new Botan::BBS;
    int seedlen=20;
    Botan::byte* seed = new Botan::byte[seedlen];
    for (int i=0;i<seedlen;i++)
    {
        seed[i]=0;
    }
    rn->add_entropy(seed,seedlen);
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
            comp="2fc7dc6a70d690ce30b66eecedc53a0bd45780bc";
            break;
        case 1:
            comp="b6caa33f65899a0e883ab851ccb55d4c700519f8";
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
BOOST_AUTO_TEST_CASE(test_bbs_non_determ)
{
    // init the lib
    Botan::InitializerOptions init_options("");
    Botan::LibraryInitializer init(init_options);

    /**
    * init
    */
    Botan::RandomNumberGenerator* rn1 = (Botan::RandomNumberGenerator*) new Botan::BBS;
    Botan::RandomNumberGenerator* rn2 = (Botan::RandomNumberGenerator*) new Botan::BBS;
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

        //SecureVector<byte> res = decode_hex(comp);
        BOOST_CHECK_MESSAGE(hex_encode(out_for_rn1.begin(),out_for_rn1.size())!=hex_encode(out_for_rn2.begin(),out_for_rn2.size() ), "result was deterministic");
    }
    delete[] out;
    delete rn1;
    delete rn2;
}
#endif
