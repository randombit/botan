/*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves_instance.h>

#include <botan/internal/pcurves_wrap.h>

namespace Botan::PCurve {

namespace {

namespace brainpool256t1 {


// clang-format off
class Params final : public EllipticCurveParameters<
   "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
   "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5374",
   "662C61C430D84EA4FE66A7733D0B76B7BF93EBC4AF2F49256AE58101FEE92B04",
   "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
   "A3E8EB3CC1CFE7B7732213B23A656149AFA142C47AAFBC2B79A191562E1305F4",
   "2D996C823439C56D7F7B22E14644417E69BCB6DE39D027001DABE8F35B25C9BE"> {
};
// clang-format on

class Curve final : public EllipticCurve<Params> {
   public:
      // Return the square of the inverse of x
      static constexpr FieldElement fe_invert2(const FieldElement& x) {
         // Generated using https://github.com/mmcloughlin/addchain
         auto t18 = x.square();
         auto t8 = t18.square();
         auto t6 = t8 * x;
         auto t13 = t18 * t6;
         auto t1 = t13 * x;
         auto t4 = t1 * x;
         auto t17 = t1 * t13;
         auto t9 = t17 * t18;
         auto t5 = t18 * t9;
         auto t15 = t18 * t5;
         auto z = t15 * t18;
         auto t11 = t18 * z;
         auto t3 = t11 * t8;
         auto t2 = t18 * t3;
         auto t14 = t18 * t2;
         auto t0 = t1 * t14;
         auto t7 = t0 * t1;
         auto t16 = t18 * t7;
         auto t12 = t16 * t18;
         t1 = t12 * t18;
         auto t10 = t1 * t8;
         t8 = t10 * t18;
         auto t19 = t8 * z;
         t19.square_n(6);
         t19 *= t8;
         t18 *= t19;
         t18.square_n(7);
         t18 *= t12;
         t18.square_n(6);
         t18 *= t2;
         t18.square_n(7);
         t18 *= t1;
         t18.square_n(7);
         t18 *= t14;
         t18.square_n(6);
         t18 *= t10;
         t18.square_n(5);
         t18 *= t15;
         t18.square_n(6);
         t18 *= t5;
         t18.square_n(5);
         t17 *= t18;
         t17.square_n(9);
         t17 *= t2;
         t17.square_n(8);
         t16 *= t17;
         t16.square_n(10);
         t15 *= t16;
         t15.square_n(8);
         t14 *= t15;
         t14.square_n(8);
         t14 *= t10;
         t14.square_n(8);
         t13 *= t14;
         t13.square_n(9);
         t12 *= t13;
         t12.square_n(5);
         t11 *= t12;
         t11.square_n(8);
         t11 *= t1;
         t11.square_n(9);
         t10 *= t11;
         t10.square_n(6);
         t10 *= t8;
         t10.square_n(5);
         t9 *= t10;
         t9.square_n(9);
         t8 *= t9;
         t8.square_n(7);
         t8 *= t0;
         t8.square_n(8);
         t7 *= t8;
         t7.square_n(10);
         t6 *= t7;
         t6.square_n(6);
         t6 *= x;
         t6.square_n(13);
         t5 *= t6;
         t5.square_n(5);
         t4 *= t5;
         t4.square_n(11);
         t3 *= t4;
         t3.square_n(8);
         t2 *= t3;
         t2.square_n(7);
         t1 *= t2;
         t1.square_n(8);
         t0 *= t1;
         t0.square_n(5);
         z *= t0;
         z.square_n(2);
         z *= x;
         z.square_n(2);
         return z;
      }

      // Return the square root of this field element (if it is a quadratic residue)
      static constexpr FieldElement fe_sqrt(const FieldElement& x) {
         // Generated using https://github.com/mmcloughlin/addchain
         auto t18 = x.square();
         auto t8 = t18.square();
         auto t6 = t8 * x;
         auto t13 = t18 * t6;
         auto z = t13 * x;
         auto t4 = x * z;
         auto t17 = t13 * z;
         auto t9 = t17 * t18;
         auto t5 = t18 * t9;
         auto t15 = t18 * t5;
         auto t11 = t15 * t8;
         auto t3 = t11 * t8;
         auto t2 = t18 * t3;
         auto t14 = t18 * t2;
         auto t0 = t14 * z;
         z = t0 * x;
         z *= t6;
         auto t7 = t18 * z;
         auto t16 = t18 * t7;
         auto t12 = t16 * t18;
         auto t1 = t12 * t18;
         auto t10 = t1 * t8;
         t8 = t10 * t18;
         auto t19 = t10 * t11;
         t19.square_n(6);
         t19 *= t8;
         t18 *= t19;
         t18.square_n(7);
         t18 *= t12;
         t18.square_n(6);
         t18 *= t2;
         t18.square_n(7);
         t18 *= t1;
         t18.square_n(7);
         t18 *= t14;
         t18.square_n(6);
         t18 *= t10;
         t18.square_n(5);
         t18 *= t15;
         t18.square_n(6);
         t18 *= t5;
         t18.square_n(5);
         t17 *= t18;
         t17.square_n(9);
         t17 *= t2;
         t17.square_n(8);
         t16 *= t17;
         t16.square_n(10);
         t15 *= t16;
         t15.square_n(8);
         t14 *= t15;
         t14.square_n(8);
         t14 *= t10;
         t14.square_n(8);
         t13 *= t14;
         t13.square_n(9);
         t12 *= t13;
         t12.square_n(5);
         t11 *= t12;
         t11.square_n(8);
         t11 *= t1;
         t11.square_n(9);
         t10 *= t11;
         t10.square_n(6);
         t10 *= t8;
         t10.square_n(5);
         t9 *= t10;
         t9.square_n(9);
         t8 *= t9;
         t8.square_n(7);
         t8 *= t0;
         t8.square_n(8);
         t7 *= t8;
         t7.square_n(10);
         t6 *= t7;
         t6.square_n(6);
         t6 *= x;
         t6.square_n(13);
         t5 *= t6;
         t5.square_n(5);
         t4 *= t5;
         t4.square_n(11);
         t3 *= t4;
         t3.square_n(8);
         t2 *= t3;
         t2.square_n(7);
         t1 *= t2;
         t1.square_n(8);
         t0 *= t1;
         t0.square_n(6);
         z *= t0;
         z = z.square();
         return z;
      }

      // Return the inverse of an integer modulo the order
      static constexpr Scalar scalar_invert(const Scalar& x) {
         // Generated using https://github.com/mmcloughlin/addchain
         auto t13 = x.square();
         auto t10 = t13 * x;
         auto z = t10 * t13;
         auto t9 = t13 * z;
         auto t1 = t13 * t9;
         auto t11 = t1 * t13;
         auto t7 = t11 * t13;
         auto t4 = t13 * t7;
         auto t8 = t13 * t4;
         auto t12 = t13 * t8;
         auto t0 = t12 * t13;
         auto t2 = t0 * t13;
         auto t5 = t13 * t2;
         auto t6 = t13 * t5;
         auto t3 = t13 * t6;
         t13 *= t3;
         auto t14 = t11 * t13;
         t14.square_n(6);
         t14 *= t13;
         t14 = t14.square();
         t14 *= x;
         t14.square_n(5);
         t14 *= t7;
         t14.square_n(6);
         t14 *= t2;
         t14.square_n(5);
         t14 *= t6;
         t14.square_n(6);
         t14 *= t3;
         t14.square_n(8);
         t14 *= t4;
         t14.square_n(6);
         t14 *= t3;
         t14.square_n(4);
         t14 *= z;
         t14.square_n(7);
         t14 *= t6;
         t14.square_n(2);
         t14 *= t10;
         t14.square_n(9);
         t13 *= t14;
         t13.square_n(7);
         t13 *= t5;
         t13 = t13.square();
         t13 *= x;
         t13.square_n(10);
         t13 *= t0;
         t13.square_n(3);
         t13 *= x;
         t13.square_n(9);
         t12 *= t13;
         t12.square_n(4);
         t11 *= t12;
         t11.square_n(8);
         t11 *= t9;
         t11.square_n(7);
         t11 *= t7;
         t11.square_n(4);
         t11 *= t9;
         t11.square_n(5);
         t11 *= t10;
         t11.square_n(5);
         t10 *= t11;
         t10.square_n(7);
         t9 *= t10;
         t9.square_n(7);
         t9 *= t2;
         t9.square_n(5);
         t9 *= t0;
         t9.square_n(6);
         t8 *= t9;
         t8.square_n(5);
         t8 *= t6;
         t8.square_n(6);
         t8 *= t0;
         t8 = t8.square();
         t8 *= x;
         t8.square_n(8);
         t7 *= t8;
         t7.square_n(7);
         t7 *= t6;
         t7.square_n(5);
         t6 *= t7;
         t6.square_n(5);
         t5 *= t6;
         t5.square_n(11);
         t4 *= t5;
         t4.square_n(10);
         t3 *= t4;
         t3.square_n(8);
         t3 *= z;
         t3.square_n(7);
         t2 *= t3;
         t2.square_n(5);
         t1 *= t2;
         t1.square_n(9);
         t1 *= t0;
         t1.square_n(5);
         t0 *= t1;
         t0.square_n(5);
         z *= t0;
         return z;
      }
};

}  // namespace brainpool256t1

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::brainpool256t1() {
   return PrimeOrderCurveImpl<brainpool256t1::Curve>::instance();
}

}  // namespace Botan::PCurve
