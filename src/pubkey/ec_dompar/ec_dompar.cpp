
#include <botan/ec_dompar.h>
#include <botan/enums.h>
#include <botan/parsing.h>
#include <botan/libstate.h>
#include <botan/hex.h>
#include <botan/pipe.h>

namespace Botan {

namespace {

std::vector<std::string> get_standard_domain_parameter(const std::string& oid)
   {
   /*
   GEC 2: Test Vectors for SEC 1
   Certicom Research
   Working Draft
   September, 1999
   Version 0.3;
   section 2.1.2
   */
   if(oid == "1.3.132.0.8")
      {
      std::vector<std::string> dom_par;
      dom_par.push_back("0xffffffffffffffffffffffffffffffff7fffffff"); //p
      dom_par.push_back("0xffffffffffffffffffffffffffffffff7ffffffc"); // a
      dom_par.push_back("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45"); // b
      dom_par.push_back("024a96b5688ef573284664698968c38bb913cbfc82"); // G
      dom_par.push_back("0x0100000000000000000001f4c8f927aed3ca752257"); // order
      dom_par.push_back("1");                                         // cofactor
      return dom_par;
      }

   if(oid == "1.2.840.10045.3.1.1") // prime192v1 Flexiprovider
      {
      std::vector<std::string> dom_par;
      dom_par.push_back("0xfffffffffffffffffffffffffffffffeffffffffffffffff"); //p
      dom_par.push_back("0xfffffffffffffffffffffffffffffffefffffffffffffffc"); // a
      dom_par.push_back("0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1"); // b
      dom_par.push_back("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"); // G
      dom_par.push_back("0xffffffffffffffffffffffff99def836146bc9b1b4d22831"); // order
      dom_par.push_back("1");                                         // cofactor
      }

   /* prime192v2; source: Flexiprovider */
   if(oid == "1.2.840.10045.3.1.2")
      {
      std::vector<std::string> dom_par;
      dom_par.push_back("0xfffffffffffffffffffffffffffffffeffffffffffffffff"); //p
      dom_par.push_back("0xffffffffffffffffffffffffffffffFeffffffffffffffFC"); // a
      dom_par.push_back("0xcc22d6dfb95c6b25e49c0d6364a4e5980c393aa21668d953"); // b
      dom_par.push_back("03eea2bae7e1497842f2de7769cfe9c989c072ad696f48034a"); // G
      dom_par.push_back("0xfffffffffffffffffffffffe5fb1a724dc80418648d8dd31"); // order
      dom_par.push_back("1");                                         // cofactor
      }

   /* prime192v3; source: Flexiprovider */
   if(oid == "1.2.840.10045.3.1.3")
      {
      std::vector<std::string> dom_par;
      dom_par.push_back("0xfffffffffffffffffffffffffffffffeffffffffffffffff"); //p
      dom_par.push_back("0xfffffffffffffffffffffffffffffffefffffffffffffffc"); // a
      dom_par.push_back("0x22123dc2395a05caa7423daeccc94760a7d462256bd56916"); // b
      dom_par.push_back("027d29778100c65a1da1783716588dce2b8b4aee8e228f1896"); // G
      dom_par.push_back("0xffffffffffffffffffffffff7a62d031c83f4294f640ec13"); // order
      dom_par.push_back("1");                                         // cofactor
      }

   /* prime239v1; source: Flexiprovider */
   if(oid == "1.2.840.10045.3.1.4")
      {
      std::vector<std::string> dom_par;
      dom_par.push_back("0x7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff"); //p
      dom_par.push_back("0x7ffFffffffffffffffffffff7fffffffffff8000000000007ffffffffffc"); // a
      dom_par.push_back("0x6B016C3BDCF18941D0D654921475CA71A9DB2FB27D1D37796185C2942C0A"); // b
      dom_par.push_back("020ffA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF"); // G
      dom_par.push_back("0x7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b"); // order
      dom_par.push_back("1");                                         // cofactor
      }

   /* prime239v2; source: Flexiprovider */
   if(oid == "1.2.840.10045.3.1.5")
      {
      std::vector<std::string> dom_par;
      dom_par.push_back("0x7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff"); //p
      dom_par.push_back("0x7ffFffffffffffffffffffff7ffFffffffff8000000000007ffFffffffFC"); // a
      dom_par.push_back("0x617FAB6832576CBBFED50D99F0249C3FEE58B94BA0038C7AE84C8C832F2C"); // b
      dom_par.push_back("0238AF09D98727705120C921BB5E9E26296A3CDCF2F35757A0EAFD87B830E7"); // G
      dom_par.push_back("0x7fffffffffffffffffffffff800000CFA7E8594377D414C03821BC582063"); // order
      dom_par.push_back("1");                                         // cofactor
      }

   /* prime239v3; source: Flexiprovider */
   if(oid == "1.2.840.10045.3.1.6")
      {
      std::vector<std::string> dom_par;
      dom_par.push_back("0x7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff"); //p
      dom_par.push_back("0x7ffFffffffffffffffffffff7ffFffffffff8000000000007ffFffffffFC"); // a
      dom_par.push_back("0x255705FA2A306654B1F4CB03D6A750A30C250102D4988717D9BA15AB6D3E"); // b
      dom_par.push_back("036768AE8E18BB92CFCF005C949AA2C6D94853D0E660BBF854B1C9505FE95A"); // G
      dom_par.push_back("0x7fffffffffffffffffffffff7fffff975DEB41B3A6057C3C432146526551"); // order
      dom_par.push_back("1");                                         // cofactor
      }

   /* prime256v1; source:    Flexiprovider */
   if(oid == "1.2.840.10045.3.1.7")
      {
      std::vector<std::string> dom_par;
      dom_par.push_back("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"); //p
      dom_par.push_back("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffFC"); // a
      dom_par.push_back("0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"); // b
      dom_par.push_back("036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"); // G
      dom_par.push_back("0xffffffff00000000ffffffffffffffffBCE6FAADA7179E84F3B9CAC2FC632551"); // order
      dom_par.push_back("1");                                         // cofactor
      }

   throw Invalid_Argument("No such ECC curve " + oid);

   // Todo, add SEC2, Brainpool, NIST curves
   }

EC_Domain_Params get_ec_dompar(const std::string& oid)
   {
   std::vector<std::string> dom_par = get_standard_domain_parameter(oid);

   BigInt p(dom_par[0]); // give as 0x...
   GFpElement a(p, BigInt(dom_par[1]));
   GFpElement b(p, BigInt(dom_par[2]));

   Pipe pipe(new Hex_Decoder);
   pipe.process_msg(dom_par[3]);
   SecureVector<byte> sv_g = pipe.read_all();

   CurveGFp curve(a, b, p);
   PointGFp G = OS2ECP ( sv_g, curve );
   G.check_invariants();
   BigInt order(dom_par[4]);
   BigInt cofactor(dom_par[5]);
   EC_Domain_Params result(curve, G, order, cofactor);
   return result;
   }

}

EC_Domain_Params get_EC_Dom_Pars_by_oid(std::string oid)
   {
   EC_Domain_Params result = get_ec_dompar(oid);
   result.m_oid = oid;
   return result;
   }

EC_Domain_Params::EC_Domain_Params(const CurveGFp& curve, const PointGFp& base_point,
                                   const BigInt& order, const BigInt& cofactor)
   : m_curve(curve),
     m_base_point(base_point),
     m_order(order),
     m_cofactor(cofactor),
     m_oid("")
   { }

namespace {

SecureVector<byte> encode_der_ec_dompar_explicit(EC_Domain_Params const& dom_pars)
   {
   u32bit ecpVers1 = 1;
   OID curve_type_oid("1.2.840.10045.1.1");

   DER_Encoder der;

   der.start_cons(SEQUENCE)
         .encode(ecpVers1)
         .start_cons(SEQUENCE)
            .encode(curve_type_oid)
            .encode(dom_pars.get_curve().get_p())
         .end_cons()
         .start_cons(SEQUENCE)
            .encode(FE2OSP ( dom_pars.get_curve().get_a() ), OCTET_STRING)
            .encode(FE2OSP ( dom_pars.get_curve().get_b() ), OCTET_STRING)
         .end_cons()
         .encode(EC2OSP ( dom_pars.get_base_point(), PointGFp::UNCOMPRESSED), OCTET_STRING)
         .encode(dom_pars.get_order())
         .encode(dom_pars.get_cofactor())
      .end_cons();

   return der.get_contents();
   }

EC_Domain_Params decode_ber_ec_dompar_explicit(SecureVector<byte> const& encoded)
   {
   BigInt ecpVers1(1);
   OID curve_type_oid;
   SecureVector<byte> sv_a;
   SecureVector<byte> sv_b;
   BigInt p;
   SecureVector<byte> sv_base_point;
   BigInt order;
   BigInt cofactor;
   BER_Decoder dec(encoded);
   dec
      .start_cons(SEQUENCE)
      .decode(ecpVers1)
      .start_cons(SEQUENCE)
      .decode(curve_type_oid)
      .decode(p)
      .end_cons()
      .start_cons(SEQUENCE)
      .decode(sv_a, OCTET_STRING)
      .decode(sv_b, OCTET_STRING)
      .end_cons()
      .decode(sv_base_point, OCTET_STRING)
      .decode(order)
      .decode(cofactor)
      .verify_end()
      .end_cons();
   if(ecpVers1 != 1)
      {
      throw Decoding_Error("wrong ecpVers");
      }
   // Set the domain parameters
   if(curve_type_oid.as_string() != "1.2.840.10045.1.1") // NOTE: hardcoded: prime field type
      {
      throw Decoding_Error("wrong curve type oid where prime field was expected");
      }
   GFpElement a(p,BigInt::decode(sv_a, sv_a.size()));
   GFpElement b(p,BigInt::decode(sv_b, sv_b.size()));
   CurveGFp curve(a,b,p);
   PointGFp G = OS2ECP ( sv_base_point, curve );
   G.check_invariants();
   return EC_Domain_Params(curve, G, order, cofactor);
   }

} // end anonymous namespace

SecureVector<byte> encode_der_ec_dompar(EC_Domain_Params const& dom_pars, EC_dompar_enc enc_type)
     {
     SecureVector<byte> result;

     if(enc_type == ENC_EXPLICIT)
        {
        result = encode_der_ec_dompar_explicit(dom_pars);
        }
     else if(enc_type == ENC_OID)
        {
        OID dom_par_oid(dom_pars.get_oid());
        result = DER_Encoder().encode(dom_par_oid).get_contents();
        }
     else if(enc_type == ENC_IMPLICITCA)
        {
        result = DER_Encoder().encode_null().get_contents();
        }
     else
        {
        throw Internal_Error("encountered illegal value for ec parameter encoding type");
        }
     return result;
     }

EC_Domain_Params decode_ber_ec_dompar(SecureVector<byte> const& encoded)
   {
   BER_Decoder dec(encoded);
   BER_Object obj = dec.get_next_object();
   ASN1_Tag tag = obj.type_tag;
   std::auto_ptr<EC_Domain_Params> p_result;

   if(tag == OBJECT_ID)
      {
      OID dom_par_oid;
      BER_Decoder(encoded).decode(dom_par_oid);
      return EC_Domain_Params(get_ec_dompar(dom_par_oid.as_string()));
      }
   else if(tag == SEQUENCE)
      return EC_Domain_Params(decode_ber_ec_dompar_explicit(encoded));
   else if(tag == NULL_TAG)
      throw Decoding_Error("cannot decode ECDSA parameters that are ImplicitCA");

   throw Decoding_Error("encountered unexpected when trying to decode domain parameters");
   }

bool operator==(EC_Domain_Params const& lhs, EC_Domain_Params const& rhs)
   {
   return ((lhs.get_curve() == rhs.get_curve()) &&
           (lhs.get_base_point() == rhs.get_base_point()) &&
           (lhs.get_order() == rhs.get_order()) &&
           (lhs.get_cofactor() == rhs.get_cofactor()));
   }

}

