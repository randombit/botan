
#include <botan/mldsa_comp_parameters.h>
#include <botan/oids.h>
#include <botan/asn1_obj.h>

namespace Botan {

    template<typename T>
    struct MLDSA_Composite_param_set {
        OID oid;
        std::string label;
        std::string prehash_func;
        std::string mldsa_variant;
        std::string traditional_algoritm;
       };

/*
id-MLDSA44-RSA2048-PSS-SHA256

      -  OID: 1.3.6.1.5.5.7.6.37

      -  Label: COMPSIG-MLDSA44-RSA2048-PSS-SHA256

      -  Pre-Hash function (PH): SHA256

      -  ML-DSA variant: ML-DSA-44

      -  Traditional Algorithm: RSA

         o  Traditional Signature Algorithm: id-RSASSA-PSS

         o  RSA size: 2048

         o  RSASSA-PSS parameters: See Table 2

                +=============================+===========+
                | RSASSA-PSS-params field     | Value     |
                +=============================+===========+
                | hashAlgorithm               | id-sha256 |
                +-----------------------------+-----------+
                | maskGenAlgorithm.algorithm  | id-mgf1   |
                +-----------------------------+-----------+
                | maskGenAlgorithm.parameters | id-sha256 |
                +-----------------------------+-----------+
                | saltLength                  | 32        |
                +-----------------------------+-----------+
                | trailerField                | 1         |
                +-----------------------------+-----------+

                     Table 2: RSASSA-PSS 2048 and 3072
                                 Parameters
*/
}
