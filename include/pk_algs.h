/*************************************************
* PK Key Factory Header File                     *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_PK_KEY_FACTORY_H__
#define BOTAN_PK_KEY_FACTORY_H__

#include <botan/x509_key.h>
#include <botan/pkcs8.h>

namespace Botan {

/*************************************************
* Get an PK key object                           *
*************************************************/
X509_PublicKey*   get_public_key(const std::string&);
PKCS8_PrivateKey* get_private_key(const std::string&);

}

#endif
