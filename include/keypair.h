/*************************************************
* Keypair Checks Header File                     *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_KEYPAIR_H__
#define BOTAN_KEYPAIR_H__

#include <botan/look_pk.h>

namespace Botan {

namespace KeyPair {

/*************************************************
* Check key pair consistency                     *
*************************************************/
void check_key(PK_Encryptor*, PK_Decryptor*);
void check_key(PK_Signer*, PK_Verifier*);

}

}

#endif
