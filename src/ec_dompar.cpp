#include <botan/ec_dompar.h>
#include <botan/config.h>
#include <botan/ec.h>
#include <botan/enums.h>



using namespace Botan::math::ec;
using namespace Botan::math::gf;

namespace Botan
  {
	  EC_Domain_Params get_EC_Dom_Pars_by_oid(std::string oid)
    {
      EC_Domain_Params result = Botan::global_config().get_ec_dompar(oid);
      result.m_oid = oid;
      return result;
    }
  EC_Domain_Params::EC_Domain_Params(CurveGFp const& curve, PointGFp const& base_point, BigInt const& order, BigInt const& cofactor)
      : m_curve(curve),
      m_base_point(base_point),
      m_order(order),
      m_cofactor(cofactor),
      m_oid("")
  { }
      /*EC_Domain_Params::EC_Domain_Params(string oid)
      {
          *this = Botan::global_config().get_ec_dompar(oid);
          m_oid = oid;
        // NOTE that this is the only ctor that enables the client to get domain parameters
        // with a non-empty oid. thus it is ensured that the client cannot define his own curves with an oid
      }*/
  std::ostream& operator<< ( std::ostream& output, const EC_Domain_Params& dom_par )
  {
	  output << " oid = " << dom_par.m_oid << std::endl;
	  output << "     curve = " <<  dom_par.m_curve << std::endl;
	  output << "base point = " << dom_par.m_base_point << std::endl;
	  output << "     order = " << dom_par.m_order << std::endl;
	  output << "  cofactor = " << dom_par.m_cofactor << std::endl;
    return output;
  }


  namespace
    {
    SecureVector<byte> encode_der_ec_dompar_explicit(EC_Domain_Params const& dom_pars)
    {
      u32bit ecpVers1 = 1;
      OID curve_type_oid("1.2.840.10045.1.1");
      SecureVector<byte> result = DER_Encoder()
                                  .start_cons(SEQUENCE)
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
                                  .end_cons()
                                  .get_contents();
      return result;
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

  SecureVector<byte> const encode_der_ec_dompar(EC_Domain_Params const& dom_pars, EC_dompar_enc enc_type)
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
  EC_Domain_Params const decode_ber_ec_dompar(SecureVector<byte> const& encoded)
  {
    BER_Decoder dec(encoded);
    BER_Object obj = dec.get_next_object();
    ASN1_Tag tag = obj.type_tag;
    std::auto_ptr<EC_Domain_Params> p_result;
    if(tag == OBJECT_ID)//if(tag == 6)
      {
        OID dom_par_oid;
        BER_Decoder(encoded).decode(dom_par_oid);
        p_result = std::auto_ptr<EC_Domain_Params>(new  EC_Domain_Params(Botan::global_config().get_ec_dompar(dom_par_oid.as_string())));
      }
      else if(tag == SEQUENCE) //else if(tag == 16)
      {
          p_result = std::auto_ptr<EC_Domain_Params>(new  EC_Domain_Params(decode_ber_ec_dompar_explicit(encoded)));
      }
      else if(tag == NULL_TAG)
      {
        throw Decoding_Error("cannot decode ECDSA parameters that are ImplicitCA");
      }
    else
      {
        throw Decoding_Error("encountered unexpected when trying to decode domain parameters");
      }
    return *p_result;
  }

  bool operator==(EC_Domain_Params const& lhs, EC_Domain_Params const& rhs)
  {
      return ((lhs.get_curve() == rhs.get_curve()) &&
              (lhs.get_base_point() == rhs.get_base_point()) &&
              (lhs.get_order() == rhs.get_order()) &&
              (lhs.get_cofactor() == rhs.get_cofactor()));
  }

}
