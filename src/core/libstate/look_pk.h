/*************************************************
* PK Algorithm Lookup Header File                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_PK_LOOKUP_H__
#define BOTAN_PK_LOOKUP_H__

#include <botan/pubkey.h>

namespace Botan {

/*************************************************
* Get an PK algorithm object                     *
*************************************************/
BOTAN_DLL PK_Encryptor* get_pk_encryptor(const PK_Encrypting_Key&,
                                         const std::string&);

BOTAN_DLL PK_Decryptor* get_pk_decryptor(const PK_Decrypting_Key&,
                                         const std::string&);

BOTAN_DLL PK_Signer* get_pk_signer(const PK_Signing_Key&,
                                   const std::string&,
                                   Signature_Format = IEEE_1363);

BOTAN_DLL PK_Verifier* get_pk_verifier(const PK_Verifying_with_MR_Key&,
                                       const std::string&,
                                       Signature_Format = IEEE_1363);
BOTAN_DLL PK_Verifier* get_pk_verifier(const PK_Verifying_wo_MR_Key&,
                                       const std::string&,
                                       Signature_Format = IEEE_1363);

BOTAN_DLL PK_Key_Agreement* get_pk_kas(const PK_Key_Agreement_Key&,
                                       const std::string&);

}

#endif
