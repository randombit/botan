/*************************************************
* ElGamal Source File                            *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/elgamal.h>
#include <botan/numthry.h>
#include <botan/keypair.h>
#include <botan/util.h>

namespace Botan {

/*************************************************
* ElGamal_PublicKey Constructor                  *
*************************************************/
ElGamal_PublicKey::ElGamal_PublicKey(const DL_Group& grp, const BigInt& y1)
   {
   group = grp;
   y = y1;
   X509_load_hook();
   }

/*************************************************
* Algorithm Specific X.509 Initialization Code   *
*************************************************/
void ElGamal_PublicKey::X509_load_hook()
   {
   core = ELG_Core(group, y);
   check_loaded_public();
   }

/*************************************************
* ElGamal Encryption Function                    *
*************************************************/
SecureVector<byte> ElGamal_PublicKey::encrypt(const byte in[],
                                              u32bit length) const
   {
   BigInt k = random_integer(2 * dl_work_factor(group_p().bits()));
   return core.encrypt(in, length, k);
   }

/*************************************************
* Return the maximum input size in bits          *
*************************************************/
u32bit ElGamal_PublicKey::max_input_bits() const
   {
   return (group_p().bits() - 1);
   }

/*************************************************
* ElGamal_PrivateKey Constructor                 *
*************************************************/
ElGamal_PrivateKey::ElGamal_PrivateKey(const DL_Group& grp)
   {
   group = grp;

   x = random_integer(2 * dl_work_factor(group_p().bits()));

   PKCS8_load_hook();
   check_generated_private();
   }

/*************************************************
* ElGamal_PrivateKey Constructor                 *
*************************************************/
ElGamal_PrivateKey::ElGamal_PrivateKey(const DL_Group& grp, const BigInt& x1,
                                       const BigInt& y1)
   {
   group = grp;
   y = y1;
   x = x1;

   PKCS8_load_hook();
   check_loaded_private();
   }

/*************************************************
* Algorithm Specific PKCS #8 Initialization Code *
*************************************************/
void ElGamal_PrivateKey::PKCS8_load_hook()
   {
   if(y == 0)
      y = power_mod(group_g(), x, group_p());
   core = ELG_Core(group, y, x);
   }

/*************************************************
* ElGamal Decryption Function                    *
*************************************************/
SecureVector<byte> ElGamal_PrivateKey::decrypt(const byte in[],
                                               u32bit length) const
   {
   return core.decrypt(in, length);
   }

/*************************************************
* Check Private ElGamal Parameters               *
*************************************************/
bool ElGamal_PrivateKey::check_key(bool strong) const
   {
   if(!DL_Scheme_PrivateKey::check_key(strong))
      return false;

   if(!strong)
      return true;

   try {
      KeyPair::check_key(get_pk_encryptor(*this, "EME1(SHA-1)"),
                         get_pk_decryptor(*this, "EME1(SHA-1)")
         );
      }
   catch(Self_Test_Failure)
      {
      return false;
      }

   return true;
   }

}
