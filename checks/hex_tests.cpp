/******************************************************
 * Hex Encoder/Decoder tests                          *
 *                                                    *
 * (C) 2007 Manuel Hartl                              *
 *          hartl@flexsecure.de                       *
 ******************************************************/
#include <botan/secmem.h>
#include <botan/pipe.h>
#include <botan/hex.h>
#include <botan/base.h>
#include <botan/botan.h>

using namespace Botan;
using namespace std;


BOOST_AUTO_TEST_CASE(test_hex)
{
	// init the lib
	Botan::InitializerOptions init_options("");
	Botan::LibraryInitializer init(init_options);
 	
    string comp("4040");
    SecureVector<byte> input(2);
    input[0]=64;
    input[1]=64;
    Pipe pipe(create_shared_ptr<Hex_Encoder>());
    pipe.process_msg(input);
    string result = pipe.read_all_as_string();
    // testarea
    BOOST_CHECK_MESSAGE(result==comp, "result was: " << result << " but should be " << comp);
}

