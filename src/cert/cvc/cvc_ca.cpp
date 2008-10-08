#include <botan/cvc_ca.h>
#include <botan/cvc_cert.h>
#include <botan/der_enc.h>
#include <botan/util.h>
#include <botan/oids.h>
namespace Botan {

EAC1_1_CVC EAC1_1_CVC_CA::make_cert(std::auto_ptr<PK_Signer> signer,
                                    MemoryRegion<byte> const& public_key,
                                    ASN1_Car const& car,
                                    ASN1_Chr const& chr,
                                    byte holder_auth_templ,
                                    ASN1_Ced ced,
                                    ASN1_Cex cex,
                                    RandomNumberGenerator& rng)
   {
   OID chat_oid(OIDS::lookup("CertificateHolderAuthorizationTemplate"));
   MemoryVector<byte> enc_chat_val;
   enc_chat_val.append(holder_auth_templ);

   MemoryVector<byte> enc_cpi;
   enc_cpi.append(0x00);
   MemoryVector<byte> tbs = DER_Encoder()
      .encode(enc_cpi, OCTET_STRING, ASN1_Tag(41), APPLICATION) // cpi
      .encode(car)
      .raw_bytes(public_key)
      .encode(chr)
      .start_cons(ASN1_Tag(76), APPLICATION)
      .encode(chat_oid)
      .encode(enc_chat_val, OCTET_STRING, ASN1_Tag(19), APPLICATION)
      .end_cons()
      .encode(ced)
      .encode(cex)
      .get_contents();

   MemoryVector<byte> signed_cert =
      EAC1_1_CVC::make_signed(signer,
                              EAC1_1_CVC::build_cert_body(tbs),
                              rng);

   std::tr1::shared_ptr<DataSource> source(new DataSource_Memory(signed_cert));

   return EAC1_1_CVC(source);
   }

}
