/*************************************************
* Keypair Checks Header File                     *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_KEYPAIR_H__
#define BOTAN_KEYPAIR_H__

#include <botan/look_pk.h>

namespace Botan {

namespace KeyPair {

/*************************************************
* Check key pair consistency                     *
*************************************************/
BOTAN_DLL void check_key(RandomNumberGenerator&, PK_Encryptor*, PK_Decryptor*);
BOTAN_DLL void check_key(RandomNumberGenerator&, PK_Signer*, PK_Verifier*);

}

}

#endif
