/*************************************************
* DL Scheme Source File                          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/dl_algo.h>
#include <botan/numthry.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

/*************************************************
* Return the X.509 public key encoder            *
*************************************************/
X509_Encoder* DL_Scheme_PublicKey::x509_encoder() const
   {
   class DL_Algo_Encoder : public X509_Encoder
      {
      public:
         AlgorithmIdentifier alg_id() const
            {
            return AlgorithmIdentifier(oid, group.DER_encode(group_format));
            }

         MemoryVector<byte> key_bits() const
            {
            return DER_Encoder().encode(y).get_contents();
            }

         DL_Algo_Encoder(const OID& oid, const BigInt& y,
                         const DL_Group& group,
                         const DL_Group::Format group_format)
            {
            this->oid = oid;
            this->y = y;
            this->group = group;
            this->group_format = group_format;
            }
      private:
         OID oid;
         BigInt y;
         DL_Group group;
         DL_Group::Format group_format;
      };

   return new DL_Algo_Encoder(get_oid(), y, group, group_format());
   }

/*************************************************
* Return the X.509 public key decoder            *
*************************************************/
X509_Decoder* DL_Scheme_PublicKey::x509_decoder()
   {
   class DL_Algo_Decoder : public X509_Decoder
      {
      public:
         void alg_id(const AlgorithmIdentifier& alg_id)
            {
            DataSource_Memory source(alg_id.parameters);
            key->group.BER_decode(source, key->group_format());
            }

         void key_bits(const MemoryRegion<byte>& bits)
            {
            BER_Decoder(bits).decode(key->y);
            key->X509_load_hook();
            }

         DL_Algo_Decoder(DL_Scheme_PublicKey* k) : key(k) {}
      private:
         DL_Scheme_PublicKey* key;
      };

   return new DL_Algo_Decoder(this);
   }

/*************************************************
* Return the X.509 parameters encoding           *
*************************************************/
MemoryVector<byte> DL_Scheme_PrivateKey::DER_encode_params() const
   {
   return group.DER_encode(group_format());
   }

/*************************************************
* Decode X.509 algorithm parameters              *
*************************************************/
void DL_Scheme_PrivateKey::BER_decode_params(DataSource& source)
   {
   group.BER_decode(source, group_format());
   }

/*************************************************
* Return the PKCS #8 private key encoding        *
*************************************************/
SecureVector<byte> DL_Scheme_PrivateKey::DER_encode_priv() const
   {
   return DER_Encoder().encode(x).get_contents();
   }

/*************************************************
* Decode a PKCS #8 private key encoding          *
*************************************************/
void DL_Scheme_PrivateKey::BER_decode_priv(DataSource& source)
   {
   BER_Decoder(source).decode(x);

   PKCS8_load_hook();
   check_loaded_private();
   }

/*************************************************
* Check Public DL Parameters                     *
*************************************************/
bool DL_Scheme_PublicKey::check_key(bool strong) const
   {
   if(y < 2 || y >= group_p())
      return false;
   if(!group.verify_group(strong))
      return false;
   return true;
   }

/*************************************************
* Check DL Scheme Private Parameters             *
*************************************************/
bool DL_Scheme_PrivateKey::check_key(bool strong) const
   {
   const BigInt& p = group_p();
   const BigInt& g = group_g();

   if(y < 2 || y >= p || x < 2 || x >= p)
      return false;
   if(!group.verify_group(strong))
      return false;

   if(!strong)
      return true;

   if(y != power_mod(g, x, p))
      return false;

   return true;
   }

}
