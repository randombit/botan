/*************************************************
* CMS Algorithm Specific Code Source File        *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/cms_enc.h>
#include <botan/der_enc.h>
#include <botan/lookup.h>
#include <botan/filters.h>
#include <botan/rng.h>
#include <botan/rc2.h>

namespace Botan {

namespace {

/*************************************************
* Wrap a key as specified in RFC 3217            *
*************************************************/
SecureVector<byte> do_rfc3217_wrap(const std::string& cipher,
                                   const SymmetricKey& kek,
                                   const SecureVector<byte>& input)
   {
   class Flip_Bytes : public Filter
      {
      public:
         void write(const byte data[], u32bit length)
            {
            buf.append(data, length);
            }
         void end_msg()
            {
            for(u32bit j = 0; j != buf.size(); j++)
               send(buf[buf.size()-j-1]);
            buf.destroy();
            }
         Flip_Bytes(const SecureVector<byte>& prefix) { buf.append(prefix); }
      private:
         SecureVector<byte> buf;
      };

   if(block_size_of(cipher) != 8)
      throw Encoding_Error("do_rfc3217_wrap: Bad cipher: " + cipher);

   Pipe icv(new Hash_Filter("SHA-160", 8));
   icv.process_msg(input);

   InitializationVector iv(8);
   InitializationVector fixed("4ADDA22C79E82105");

   Pipe pipe(get_cipher(cipher + "/CBC/NoPadding", kek, iv, ENCRYPTION),
             new Flip_Bytes(iv.copy()),
             get_cipher(cipher + "/CBC/NoPadding", kek, fixed, ENCRYPTION));
   pipe.start_msg();
   pipe.write(input);
   pipe.write(icv.read_all());
   pipe.end_msg();
   return pipe.read_all();
   }

}

/*************************************************
* Wrap a CEK with a KEK                          *
*************************************************/
SecureVector<byte> CMS_Encoder::wrap_key(const std::string& cipher,
                                         const SymmetricKey& cek,
                                         const SymmetricKey& kek)
   {
   if(cipher == "TripleDES")
      {
      SymmetricKey cek_parity = cek;
      cek_parity.set_odd_parity();
      return do_rfc3217_wrap(cipher, kek, cek_parity.copy());
      }
   else if(cipher == "RC2" || cipher == "CAST-128")
      {
      if(kek.length() != 16)
         throw Encoding_Error("CMS: 128-bit KEKs must be used with " + cipher);

      SecureVector<byte> lcekpad;
      lcekpad.append((byte)cek.length());
      lcekpad.append(cek.copy());
      while(lcekpad.size() % 8)
         lcekpad.append(Global_RNG::random(Nonce));
      return do_rfc3217_wrap(cipher, kek, lcekpad);
      }
   else
      throw Invalid_Argument("CMS_Encoder::wrap: Unknown cipher " + cipher);
   }

/*************************************************
* Encode the parameters for an encryption algo   *
*************************************************/
SecureVector<byte> CMS_Encoder::encode_params(const std::string& cipher,
                                              const SymmetricKey& key,
                                              const InitializationVector& iv)
   {
   DER_Encoder encoder;

   if(cipher == "RC2")
      {
      encoder.start_sequence();
      DER::encode(encoder, RC2::EKB_code(8*key.length()));
      DER::encode(encoder, iv.copy(), OCTET_STRING);
      encoder.end_sequence();
      }
   else if(cipher == "CAST-128")
      {
      encoder.start_sequence();
      DER::encode(encoder, iv.copy(), OCTET_STRING);
      DER::encode(encoder, 8*key.length());
      encoder.end_sequence();
      }
   else
      DER::encode(encoder, iv.copy(), OCTET_STRING);

   return encoder.get_contents();
   }

/*************************************************
* Generate a CEK or KEK for the cipher           *
*************************************************/
SymmetricKey CMS_Encoder::setup_key(const std::string& cipher)
   {
   u32bit keysize = 0;

   if(cipher == "TripleDES") keysize = 24;
   if(cipher == "RC2")       keysize = 16;
   if(cipher == "CAST-128")  keysize = 16;

   if(keysize == 0)
      throw Invalid_Argument("CMS: Cannot encrypt with cipher " + cipher);

   SymmetricKey key(keysize);
   if(cipher == "DES" || cipher == "TripleDES")
      key.set_odd_parity();
   return key;
   }

}
