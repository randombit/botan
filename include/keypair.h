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
void check_key(std::auto_ptr<PK_Encryptor>, std::auto_ptr<PK_Decryptor>);
void check_key(std::auto_ptr<PK_Signer>, std::auto_ptr<PK_Verifier>);

}

}

#endif
