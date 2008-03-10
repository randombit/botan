/*************************************************
* Diffie-Hellman Source File                     *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/dh.h>
#include <botan/numthry.h>
#include <botan/util.h>

namespace Botan {

/*************************************************
* DH_PublicKey Constructor                       *
*************************************************/
DH_PublicKey::DH_PublicKey(const DL_Group& grp, const BigInt& y1)
   {
   group = grp;
   y = y1;
   X509_load_hook();
   }

/*************************************************
* Algorithm Specific X.509 Initialization Code   *
*************************************************/
void DH_PublicKey::X509_load_hook()
   {
   load_check();
   }

/*************************************************
* Return the maximum input size in bits          *
*************************************************/
u32bit DH_PublicKey::max_input_bits() const
   {
   return group_p().bits();
   }

/*************************************************
* Return the public value for key agreement      *
*************************************************/
MemoryVector<byte> DH_PublicKey::public_value() const
   {
   return BigInt::encode_1363(y, group_p().bytes());
   }

/*************************************************
* Create a DH private key                        *
*************************************************/
DH_PrivateKey::DH_PrivateKey(const DL_Group& grp)
   {
   group = grp;

   const BigInt& p = group_p();
   x = random_integer(2 * dl_work_factor(p.bits()));

   PKCS8_load_hook(true);
   }

/*************************************************
* DH_PrivateKey Constructor                      *
*************************************************/
DH_PrivateKey::DH_PrivateKey(const DL_Group& grp, const BigInt& x1,
                             const BigInt& y1)
   {
   group = grp;
   y = y1;
   x = x1;

   PKCS8_load_hook();
   }

/*************************************************
* Algorithm Specific PKCS #8 Initialization Code *
*************************************************/
void DH_PrivateKey::PKCS8_load_hook(bool generated)
   {
   if(y == 0)
      y = power_mod(group_g(), x, group_p());
   core = DH_Core(group, x);

   if(generated)
      gen_check();
   else
      load_check();
   }

/*************************************************
* Return the public value for key agreement      *
*************************************************/
MemoryVector<byte> DH_PrivateKey::public_value() const
   {
   return DH_PublicKey::public_value();
   }

/*************************************************
* Derive a key                                   *
*************************************************/
SecureVector<byte> DH_PrivateKey::derive_key(const byte w[],
                                             u32bit w_len) const
   {
   return derive_key(BigInt::decode(w, w_len));
   }

/*************************************************
* Derive a key                                   *
*************************************************/
SecureVector<byte> DH_PrivateKey::derive_key(const DH_PublicKey& key) const
   {
   return derive_key(key.get_y());
   }

/*************************************************
* Derive a key                                   *
*************************************************/
SecureVector<byte> DH_PrivateKey::derive_key(const BigInt& w) const
   {
   const BigInt& p = group_p();
   if(w <= 1 || w >= p-1)
      throw Invalid_Argument(algo_name() + "::derive_key: Invalid key input");
   return BigInt::encode_1363(core.agree(w), p.bytes());
   }

}
