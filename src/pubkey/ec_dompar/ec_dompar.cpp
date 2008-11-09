
#include <botan/ec_dompar.h>
#include <botan/pubkey_enums.h>
#include <botan/parsing.h>
#include <botan/hex.h>
#include <botan/pipe.h>

namespace Botan {

namespace {

std::vector<std::string> get_standard_domain_parameter(const std::string& oid)
   {
   // using a linear search here is pretty nasty... revisit

   /* SEC2 */

   if(oid == "1.3.132.0.6")
      {
      /* secp112r1; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xdb7c2abf62e35e668076bead208b"); //p
      dom_par.push_back("0xDB7C2ABF62E35E668076BEAD2088"); // a
      dom_par.push_back("0x659EF8BA043916EEDE8911702B22"); // b
      dom_par.push_back("0409487239995A5EE76B55F9C2F098A89CE5AF8724C0A23E0E0ff77500"); // G
      dom_par.push_back("0xDB7C2ABF62E35E7628DFAC6561C5"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.132.0.7")
      {
      /* secp112r2; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xdb7c2abf62e35e668076bead208b"); //p
      dom_par.push_back("0x6127C24C05F38A0AAAF65C0EF02C"); // a
      dom_par.push_back("0x51DEF1815DB5ED74FCC34C85D709"); // b
      dom_par.push_back("044BA30AB5E892B4E1649DD0928643ADCD46F5882E3747DEF36E956E97"); // G
      dom_par.push_back("0x36DF0AAFD8B8D7597CA10520D04B"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.132.0.28")
      {
      /* secp128r1; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xfffffffdffffffffffffffffffffffff"); //p
      dom_par.push_back("0xffffffFDffffffffffffffffffffffFC"); // a
      dom_par.push_back("0xE87579C11079F43DD824993C2CEE5ED3"); // b
      dom_par.push_back("04161ff7528B899B2D0C28607CA52C5B86CF5AC8395BAFEB13C02DA292DDED7A83"); // G
      dom_par.push_back("0xffffffFE0000000075A30D1B9038A115"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.132.0.29")
      {
      /* secp128r2; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xfffffffdffffffffffffffffffffffff"); //p
      dom_par.push_back("0xD6031998D1B3BBFEBF59CC9BBff9AEE1"); // a
      dom_par.push_back("0x5EEEFCA380D02919DC2C6558BB6D8A5D"); // b
      dom_par.push_back("047B6AA5D85E572983E6FB32A7CDEBC14027B6916A894D3AEE7106FE805FC34B44"); // G
      dom_par.push_back("0x3ffffffF7ffffffFBE0024720613B5A3"); // order
      dom_par.push_back("4");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.132.0.9")
      {
      /* secp160k1; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xfffffffffffffffffffffffffffffffeffffac73"); //p
      dom_par.push_back("0x0000000000000000000000000000000000000000"); // a
      dom_par.push_back("0x0000000000000000000000000000000000000007"); // b
      dom_par.push_back("043B4C382CE37AA192A4019E763036F4F5DD4D7EBB938CF935318FDCED6BC28286531733C3F03C4FEE"); // G
      dom_par.push_back("0x0100000000000000000001B8FA16DFAB9ACA16B6B3"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.132.0.30")
      {
      /* secp160r2; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xfffffffffffffffffffffffffffffffeffffac73"); //p
      dom_par.push_back("0xffffffffffffffffffffffffffffffFEffffAC70"); // a
      dom_par.push_back("0xB4E134D3FB59EB8BAB57274904664D5AF50388BA"); // b
      dom_par.push_back("0452DCB034293A117E1F4ff11B30F7199D3144CE6DFEAffEF2E331F296E071FA0DF9982CFEA7D43F2E"); // G
      dom_par.push_back("0x0100000000000000000000351EE786A818F3A1A16B"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.132.0.31")
      {
      /* secp192k1; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xfffffffffffffffffffffffffffffffffffffffeffffee37"); //p
      dom_par.push_back("0x000000000000000000000000000000000000000000000000"); // a
      dom_par.push_back("0x000000000000000000000000000000000000000000000003"); // b
      dom_par.push_back("04DB4ff10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D"); // G
      dom_par.push_back("0xffffffffffffffffffffffFE26F2FC170F69466A74DEFD8D"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.132.0.32")
      {
      /* secp224k1; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xfffffffffffffffffffffffffffffffffffffffffffffffeffffe56d"); //p
      dom_par.push_back("0x00000000000000000000000000000000000000000000000000000000"); // a
      dom_par.push_back("0x00000000000000000000000000000000000000000000000000000005"); // b
      dom_par.push_back("04A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5"); // G
      dom_par.push_back("0x010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.132.0.33")
      {
      /* secp224r1; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xffffffffffffffffffffffffffffffff000000000000000000000001"); //p
      dom_par.push_back("0xffffffffffffffffffffffffffffffFEffffffffffffffffffffffFE"); // a
      dom_par.push_back("0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355ffB4"); // b
      dom_par.push_back("04B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"); // G
      dom_par.push_back("0xffffffffffffffffffffffffffff16A2E0B8F03E13DD29455C5C2A3D"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.132.0.10")
      {
      /* secp256k1; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"); //p
      dom_par.push_back("0x0000000000000000000000000000000000000000000000000000000000000000"); // a
      dom_par.push_back("0x0000000000000000000000000000000000000000000000000000000000000007"); // b
      dom_par.push_back("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"); // G
      dom_par.push_back("0xffffffffffffffffffffffffffffffFEBAAEDCE6AF48A03BBFD25E8CD0364141"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.132.0.34")
      {
      /* secp384r1; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"); //p
      dom_par.push_back("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFEffffffff0000000000000000ffffffFC"); // a
      dom_par.push_back("0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"); // b
      dom_par.push_back("04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"); // G
      dom_par.push_back("0xffffffffffffffffffffffffffffffffffffffffffffffffC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.132.0.35")
      {
      /* secp521r1; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); //p
      dom_par.push_back("0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFC"); // a
      dom_par.push_back("0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"); // b
      dom_par.push_back("0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2ffA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"); // G
      dom_par.push_back("0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   /* NIS */

   if(oid == "1.3.6.1.4.1.8301.3.1.2.9.0.38")
      {
      /* NIST curve P-521; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); //p
      dom_par.push_back("0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFC"); // a
      dom_par.push_back("0x051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"); // b
      dom_par.push_back("0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2ffA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"); // G
      dom_par.push_back("0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   /* BrainPool */

   if(oid == "1.3.36.3.3.2.8.1.1.1")
      {
      /* brainpoolP160r1; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xE95E4A5F737059DC60DFC7AD95B3D8139515620F"); //p
      dom_par.push_back("0x340E7BE2A280EB74E2BE61BADA745D97E8F7C300"); // a
      dom_par.push_back("0x1E589A8595423412134FAA2DBDEC95C8D8675E58"); // b
      dom_par.push_back("04BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC31667CB477A1A8EC338F94741669C976316DA6321"); // G
      dom_par.push_back("0xE95E4A5F737059DC60DF5991D45029409E60FC09"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.36.3.3.2.8.1.1.3")
      {
      /* brainpoolP192r1; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xC302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297"); //p
      dom_par.push_back("0x6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF"); // a
      dom_par.push_back("0x469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9"); // b
      dom_par.push_back("04C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD614B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F"); // G
      dom_par.push_back("0xC302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.36.3.3.2.8.1.1.5")
      {
      /* brainpoolP224r1; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xD7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF"); //p
      dom_par.push_back("0x68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43"); // a
      dom_par.push_back("0x2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B"); // b
      dom_par.push_back("040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD"); // G
      dom_par.push_back("0xD7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.36.3.3.2.8.1.1.7")
      {
      /* brainpoolP256r1; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"); //p
      dom_par.push_back("0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9"); // a
      dom_par.push_back("0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"); // b
      dom_par.push_back("048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"); // G
      dom_par.push_back("0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.36.3.3.2.8.1.1.9")
      {
      /* brainpoolP320r1; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xD35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27"); //p
      dom_par.push_back("0x3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4"); // a
      dom_par.push_back("0x520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6"); // b
      dom_par.push_back("0443BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E2061114FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1"); // G
      dom_par.push_back("0xD35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.36.3.3.2.8.1.1.11")
      {
      /* brainpoolP384r1; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53"); //p
      dom_par.push_back("0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826"); // a
      dom_par.push_back("0x4A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11"); // b
      dom_par.push_back("041D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315"); // G
      dom_par.push_back("0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

   if(oid == "1.3.36.3.3.2.8.1.1.13")
      {
      /* brainpoolP512r1; source: Flexiprovider */
      std::vector<std::string> dom_par;
      dom_par.push_back("0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3"); //p
      dom_par.push_back("0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA"); // a
      dom_par.push_back("0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723"); // b
      dom_par.push_back("0481AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F8227DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892"); // G
      dom_par.push_back("0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069"); // order
      dom_par.push_back("1");                                         // cofactor

      return dom_par;
      }

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
      return dom_par;
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
      return dom_par;
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
      return dom_par;
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
      return dom_par;
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
      return dom_par;
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
      return dom_par;
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
      return dom_par;
      }

   throw Invalid_Argument("No such ECC curve " + oid);
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

