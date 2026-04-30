/*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves_instance.h>

#include <botan/internal/pcurves_wrap.h>

namespace Botan::PCurve {

namespace {

namespace brainpool384t1 {


// clang-format off
class Params final : public EllipticCurveParameters<
   "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
   "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC50",
   "7F519EADA7BDA81BD826DBA647910F8C4B9346ED8CCDC64E4B1ABD11756DCE1D2074AA263B88805CED70355A33B471EE",
   "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
   "18DE98B02DB9A306F2AFCD7235F72A819B80AB12EBD653172476FECD462AABFFC4FF191B946A5F54D8D0AA2F418808CC",
   "25AB056962D30651A114AFD2755AD336747F93475B7A1FCA3B88F2B6A208CCFE469408584DC2B2912675BF5B9E582928"> {
};
// clang-format on

class Curve final : public EllipticCurve<Params> {
   public:
      // Return the square of the inverse of x
      static constexpr FieldElement fe_invert2(const FieldElement& x) {
         // Generated using https://github.com/mmcloughlin/addchain
         auto t1 = x.square();
         auto t0 = t1 * x;
         auto z = t0 * t1;
         auto t3 = t1 * z;
         auto t7 = t1 * t3;
         auto t10 = t1 * t7;
         auto t5 = t1 * t10;
         auto t13 = t1 * t5;
         auto t8 = t1 * t13;
         auto t2 = t1 * t8;
         auto t11 = t1 * t2;
         auto t12 = t1 * t11;
         auto t6 = t1 * t12;
         auto t9 = t1 * t6;
         auto t4 = t1 * t9;
         t1 = t4.square();
         t1 *= z;
         auto t14 = t1 * z;
         t14.square_n(2);
         t14 *= t7;
         t14.square_n(4);
         t14 *= t3;
         t14.square_n(7);
         t14 *= t8;
         t14.square_n(5);
         t14 *= t4;
         t14.square_n(10);
         t14 *= t11;
         t14.square_n(8);
         t14 *= t6;
         t14.square_n(2);
         t14 *= t0;
         t14.square_n(9);
         t14 *= t9;
         t14.square_n(5);
         t14 *= t7;
         t14.square_n(2);
         t14 *= x;
         t14.square_n(11);
         t14 *= t13;
         t14.square_n(6);
         t14 *= t12;
         t14.square_n(5);
         t14 *= t10;
         t14.square_n(5);
         t14 *= t13;
         t14.square_n(7);
         t14 *= t1;
         t14.square_n(5);
         t14 *= z;
         t14.square_n(7);
         t14 *= t3;
         t14.square_n(7);
         t14 *= t6;
         t14.square_n(10);
         t14 *= t4;
         t14.square_n(4);
         t13 *= t14;
         t13.square_n(8);
         t13 *= t11;
         t13.square_n(7);
         t13 *= t12;
         t13.square_n(5);
         t12 *= t13;
         t12.square_n(4);
         t12 *= x;
         t12.square_n(9);
         t12 *= t2;
         t12.square_n(5);
         t12 *= t9;
         t12.square_n(6);
         t11 *= t12;
         t11.square_n(6);
         t11 *= t8;
         t11.square_n(5);
         t11 *= t10;
         t11.square_n(5);
         t11 *= t10;
         t11.square_n(2);
         t11 *= x;
         t11.square_n(9);
         t11 *= t7;
         t11.square_n(5);
         t10 *= t11;
         t10.square_n(8);
         t10 *= t4;
         t10.square_n(3);
         t10 *= z;
         t10.square_n(9);
         t10 *= t6;
         t10.square_n(7);
         t10 *= t1;
         t10.square_n(2);
         t10 *= t0;
         t10.square_n(6);
         t9 *= t10;
         t9.square_n(5);
         t8 *= t9;
         t8.square_n(7);
         t7 *= t8;
         t7.square_n(8);
         t7 *= t4;
         t7.square_n(6);
         t7 *= t6;
         t7.square_n(3);
         t7 *= z;
         t7.square_n(7);
         t7 *= t4;
         t7.square_n(5);
         t7 *= t3;
         t7.square_n(5);
         t7 *= z;
         t7.square_n(7);
         t6 *= t7;
         t6.square_n(12);
         t6 *= t4;
         t6.square_n(7);
         t5 *= t6;
         t5.square_n(5);
         t5 *= t3;
         t5.square_n(5);
         t5 *= t0;
         t5.square_n(9);
         t4 *= t5;
         t4.square_n(6);
         t3 *= t4;
         t3.square_n(16);
         t2 *= t3;
         t2.square_n(4);
         t2 *= t0;
         t2.square_n(4);
         t2 *= x;
         t2.square_n(11);
         t1 *= t2;
         t1.square_n(3);
         t0 *= t1;
         t0.square_n(6);
         z *= t0;
         z.square_n(4);
         return z;
      }

      // Return the square root of this field element (if it is a quadratic residue)
      static constexpr FieldElement fe_sqrt(const FieldElement& x) {
         // Generated using https://github.com/mmcloughlin/addchain
         auto t1 = x.square();
         auto t0 = t1 * x;
         auto t7 = t0 * t1;
         auto t3 = t1 * t7;
         auto t8 = t1 * t3;
         auto t11 = t1 * t8;
         auto t5 = t1 * t11;
         auto t13 = t1 * t5;
         auto t9 = t1 * t13;
         auto t2 = t1 * t9;
         auto z = t1 * t2;
         auto t12 = t1 * z;
         auto t6 = t1 * t12;
         auto t10 = t1 * t6;
         auto t4 = t1 * t10;
         t1 = t4.square();
         t1 *= t7;
         auto t14 = t1 * t7;
         t14.square_n(2);
         t14 *= t8;
         t14.square_n(4);
         t14 *= t3;
         t14.square_n(7);
         t14 *= t9;
         t14.square_n(5);
         t14 *= t4;
         t14.square_n(10);
         t14 *= z;
         t14.square_n(8);
         t14 *= t6;
         t14.square_n(2);
         t14 *= t0;
         t14.square_n(9);
         t14 *= t10;
         t14.square_n(5);
         t14 *= t8;
         t14.square_n(2);
         t14 *= x;
         t14.square_n(11);
         t14 *= t13;
         t14.square_n(6);
         t14 *= t12;
         t14.square_n(5);
         t14 *= t11;
         t14.square_n(5);
         t14 *= t13;
         t14.square_n(7);
         t14 *= t1;
         t14.square_n(5);
         t14 *= t7;
         t14.square_n(7);
         t14 *= t3;
         t14.square_n(7);
         t14 *= t6;
         t14.square_n(10);
         t14 *= t4;
         t14.square_n(4);
         t13 *= t14;
         t13.square_n(8);
         t13 *= z;
         t13.square_n(7);
         t13 *= t12;
         t13.square_n(5);
         t12 *= t13;
         t12.square_n(4);
         t12 *= x;
         t12.square_n(9);
         t12 *= t2;
         t12.square_n(5);
         t12 *= t10;
         t12.square_n(6);
         t12 *= z;
         t12.square_n(6);
         t12 *= t9;
         t12.square_n(5);
         t12 *= t11;
         t12.square_n(5);
         t12 *= t11;
         t12.square_n(2);
         t12 *= x;
         t12.square_n(9);
         t12 *= t8;
         t12.square_n(5);
         t11 *= t12;
         t11.square_n(8);
         t11 *= t4;
         t11.square_n(3);
         t11 *= t7;
         t11.square_n(9);
         t11 *= t6;
         t11.square_n(7);
         t11 *= t1;
         t11.square_n(2);
         t11 *= t0;
         t11.square_n(6);
         t10 *= t11;
         t10.square_n(5);
         t9 *= t10;
         t9.square_n(7);
         t8 *= t9;
         t8.square_n(8);
         t8 *= t4;
         t8.square_n(6);
         t8 *= t6;
         t8.square_n(3);
         t8 *= t7;
         t8.square_n(7);
         t8 *= t4;
         t8.square_n(5);
         t8 *= t3;
         t8.square_n(5);
         t7 *= t8;
         t7.square_n(7);
         t6 *= t7;
         t6.square_n(12);
         t6 *= t4;
         t6.square_n(7);
         t5 *= t6;
         t5.square_n(5);
         t5 *= t3;
         t5.square_n(5);
         t5 *= t0;
         t5.square_n(9);
         t4 *= t5;
         t4.square_n(6);
         t3 *= t4;
         t3.square_n(16);
         t2 *= t3;
         t2.square_n(4);
         t2 *= t0;
         t2.square_n(4);
         t2 *= x;
         t2.square_n(11);
         t1 *= t2;
         t1.square_n(3);
         t0 *= t1;
         t0.square_n(8);
         z *= t0;
         return z;
      }

      // Return the inverse of an integer modulo the order
      static constexpr Scalar scalar_invert(const Scalar& x) {
         // Generated using https://github.com/mmcloughlin/addchain
         auto t8 = x.square();
         auto z = t8 * x;
         auto t18 = t8 * z;
         auto t19 = t18 * t8;
         auto t6 = t19 * x;
         auto t2 = t6 * x;
         auto t17 = t2 * t8;
         auto t22 = t17 * t8;
         auto t12 = t22 * t8;
         auto t5 = t12 * t8;
         auto t9 = t22 * t6;
         auto t3 = t8 * t9;
         auto t4 = t3 * t8;
         auto t15 = t4 * t8;
         auto t11 = t15 * t8;
         auto t13 = t11 * t8;
         auto t14 = t13 * t8;
         auto t1 = t14 * t8;
         auto t0 = t1 * t6;
         auto t10 = t0 * t8;
         auto t20 = t10 * t8;
         auto t7 = t20 * t8;
         auto t21 = t7 * t8;
         auto t16 = t20 * t6;
         t6 *= t21;
         t8 *= t6;
         auto t23 = t2 * t8;
         t23.square_n(6);
         t23 *= t3;
         t23.square_n(8);
         t23 *= t1;
         t23.square_n(4);
         t22 *= t23;
         t22.square_n(10);
         t22 *= t9;
         t22.square_n(9);
         t22 *= t21;
         t22.square_n(6);
         t22 *= t14;
         t22.square_n(6);
         t22 *= t10;
         t22.square_n(5);
         t22 *= t18;
         t22.square_n(13);
         t22 *= t8;
         t22.square_n(6);
         t22 *= t11;
         t22.square_n(7);
         t22 *= t16;
         t22.square_n(6);
         t22 *= t20;
         t22.square_n(5);
         t22 *= t4;
         t22.square_n(7);
         t22 *= t14;
         t22.square_n(6);
         t21 *= t22;
         t21.square_n(3);
         t21 *= x;
         t21.square_n(11);
         t21 *= t6;
         t21.square_n(3);
         t21 *= t19;
         t21.square_n(8);
         t21 *= t9;
         t21.square_n(8);
         t20 *= t21;
         t20.square_n(4);
         t19 *= t20;
         t19.square_n(9);
         t19 *= t14;
         t19.square_n(8);
         t19 *= t8;
         t19.square_n(5);
         t19 *= t9;
         t19.square_n(4);
         t18 *= t19;
         t18.square_n(9);
         t18 *= t0;
         t18.square_n(5);
         t18 *= t17;
         t18.square_n(8);
         t18 *= t7;
         t18.square_n(4);
         t18 *= t12;
         t18.square_n(7);
         t17 *= t18;
         t17.square_n(8);
         t16 *= t17;
         t16.square_n(7);
         t15 *= t16;
         t15.square_n(8);
         t15 *= t0;
         t15.square_n(13);
         t14 *= t15;
         t14.square_n(8);
         t14 *= t10;
         t14.square_n(7);
         t13 *= t14;
         t13.square_n(6);
         t12 *= t13;
         t12.square_n(7);
         t11 *= t12;
         t11.square_n(7);
         t10 *= t11;
         t10.square_n(5);
         t9 *= t10;
         t9.square_n(7);
         t9 *= t8;
         t9.square_n(6);
         t9 *= t0;
         t9.square_n(7);
         t8 *= t9;
         t8.square_n(3);
         t8 *= t3;
         t8.square_n(10);
         t7 *= t8;
         t7.square_n(12);
         t6 *= t7;
         t6.square_n(5);
         t5 *= t6;
         t5.square_n(10);
         t4 *= t5;
         t4.square_n(12);
         t3 *= t4;
         t3.square_n(5);
         t2 *= t3;
         t2.square_n(11);
         t1 *= t2;
         t1.square_n(8);
         t0 *= t1;
         t0.square_n(5);
         z *= t0;
         return z;
      }
};

}  // namespace brainpool384t1

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::brainpool384t1() {
   return PrimeOrderCurveImpl<brainpool384t1::Curve>::instance();
}

}  // namespace Botan::PCurve
