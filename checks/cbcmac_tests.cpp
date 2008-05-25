/******************************************************
* cbc-mac tests                                       *
*                                                     *
* (C) 2007 Manuel Hartl                               *
*          hartl@flexsecure.de                        *
******************************************************/

#include <iostream>
#include <fstream>

#include <botan/cbc_mac.h>

BOOST_AUTO_TEST_CASE(test_cbcmac)
{
	cout << "." << flush;
    // init the lib
    Botan::InitializerOptions init_options("");
    Botan::LibraryInitializer init(init_options);

    int keylen = 16;
    Botan::byte* key = new Botan::byte[keylen];

    for (int i=0;i<16;i++)
    {
        key[i]=0;
    }

    int datalen = 16;
    Botan::byte* data = new Botan::byte[datalen];
    for (int i=0;i<16;i++)
    {
        data[i]=0;
    }

    Botan::CBC_MAC mac = Botan::CBC_MAC("AES");
    mac.set_key(key,keylen);
    mac.update(data,datalen);
    Botan::SecureVector<Botan::byte> result = mac.final();

    // reference value from Bouncy Castle (CBC-MAC/AES128)
    string str_expected("66e94bd4ef8a2c3b884cfa59ca342b2e");
    Botan::SecureVector<Botan::byte> expected = decode_hex(str_expected);

    BOOST_CHECK(result == expected);

    result.destroy();
    delete[](key);
    delete[](data);
}
