/*************************************************
* PK Algorithm Lookup Header File                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_PK_LOOKUP_H__
#define BOTAN_PK_LOOKUP_H__

#include <botan/pubkey.h>

namespace Botan {

/*************************************************
* Get an PK algorithm object                     *
*************************************************/
PK_Encryptor* get_pk_encryptor(const PK_Encrypting_Key&, const std::string&);
PK_Decryptor* get_pk_decryptor(const PK_Decrypting_Key&, const std::string&);

PK_Signer*    get_pk_signer(const PK_Signing_Key&, const std::string&,
                            Signature_Format = IEEE_1363);

PK_Verifier*  get_pk_verifier(const PK_Verifying_with_MR_Key&,
                              const std::string&,
                              Signature_Format = IEEE_1363);
PK_Verifier*  get_pk_verifier(const PK_Verifying_wo_MR_Key&,
                              const std::string&,
                              Signature_Format = IEEE_1363);

PK_Key_Agreement* get_pk_kas(const PK_Key_Agreement_Key&, const std::string&);

}

#endif
