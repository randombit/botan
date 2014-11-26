/**
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 *
 * Distributed under the terms of the Botan license
 *
 */

#ifndef __mce_overbeck_cca2__H_
#define __mce_overbeck_cca2__H_

#include <botan/pk_ops.h>
#include <botan/mceliece_key.h>
#include <botan/mceliece.h>
#include <botan/types.h>
#include <botan/secmem.h>

namespace Botan
{
class BOTAN_DLL McEliece_Overbeck_CCA2_Public_Operation : public PK_Ops::Encryption
{
  public:
  McEliece_Overbeck_CCA2_Public_Operation(const McEliece_PublicKey& public_key);

  size_t max_input_bits() const { return 512; };
  secure_vector<byte> encrypt(const byte msg[], size_t msg_len, RandomNumberGenerator&);

  private:
  McEliece_Public_Operation m_raw_pub_op;
};

class BOTAN_DLL McEliece_Overbeck_CCA2_Private_Operation : public PK_Ops::Decryption
  {
    public:
      McEliece_Overbeck_CCA2_Private_Operation(const McEliece_PrivateKey& mce_key);

      size_t max_input_bits() const { return (m_raw_priv_op.max_input_bits()+7)/8*8 + 2*512; };


secure_vector<byte> decrypt(const byte msg[], size_t msg_len);
    private:
      McEliece_Private_Operation m_raw_priv_op;
  };
}

#endif /* h-guard */
