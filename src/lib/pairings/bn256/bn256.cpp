/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bn256.h>
#include <botan/bigint.h>
#include <botan/numthry.h>
#include <botan/internal/monty.h>
#include <vector>
#include <sstream>



// Remove these:
#include <iostream>
#include <botan/hex.h>

namespace Botan {

namespace BN_256_Impl {

namespace {

class Params
   {
   public:

      // Just move all of these to GFp1??

      static std::shared_ptr<Montgomery_Params> monty()
         {
         static std::shared_ptr<Montgomery_Params> monty = std::make_shared<Montgomery_Params>(p());
         return monty;
         }

      static BigInt inv_mod_p(const BigInt& x)
         {
         // return ct_inverse_mod_odd_modulus(x, p());
         return power_mod(x, p() - 2, p());
         }

      static const BigInt& p()
         {
         static const BigInt p("0x8fb501e34aa387f9aa6fecb86184dc21ee5b88d120b5b59e185cac6c5e089667");
         return p;
         }

      static const BigInt& R1()
         {
         // 2**256 % p
         static const BigInt R1("0x704afe1cb55c7806559013479e7b23de11a4772edf4a4a61e7a35393a1f76999");
         return R1;
         }

      static const BigInt& R2()
         {
         // (R*R) % p
         static const BigInt R2("0x7c36e0e62c2380b70c6dc37b80fb1651409ed151b2efb0c29c21c3ff7e444f56");
         return R2;
         }

      static const BigInt& R3()
         {
         // (R*R*R) % p
         static const BigInt R3("0x24ebbbb3a2529292df2ff66396b107a7388f899054f538a42af2dfb9324a5bb8");
         return R3;
         }

      static const BigInt& N()
         {
         //N = R1 - inverse_mod(p, R1)
         static const BigInt N("0x38997ae661c3ef3c2524282f48054c12734b3343ab8513c82387f9007f17daa9");
         return N;
         }
   };

class GFp1 final : public Params
   {
   public:
      GFp1(const BigInt& v, bool redc_needed = true) :
         m_v(monty(), v, redc_needed)
         {
         }

      GFp1(const uint8_t bits[]) : m_v(monty(), bits, 32)
         {
         }

      GFp1(const Montgomery_Int& v) : m_v(v) {}

      bool operator==(const GFp1& other) const { return m_v == other.m_v; }
      bool operator!=(const GFp1& other) const { return !(*this == other); }

      static GFp1 one()
         {
         return GFp1(monty()->R1(), false);
         }

      static GFp1 zero()
         {
         return GFp1(0, false);
         }

      static GFp1 curve_B()
         {
         return GFp1(3);
         }

      static size_t size() { return 32; }

      std::vector<uint8_t> serialize() const
         {
         std::vector<uint8_t> v(GFp1::size());
         BigInt::encode_1363(v.data(), v.size(), value());
         return v;
         }

      bool is_one() const { return m_v.is_one(); }
      bool is_zero() const { return m_v.is_zero(); }

      BigInt value() const { return m_v.value(); }

      GFp1 operator+(const GFp1& other) const
         {
         return GFp1(m_v + other.m_v);
         }

      GFp1 operator-(const GFp1& other) const
         {
         return GFp1(m_v - other.m_v);
         }

      GFp1& operator+=(const GFp1& other)
         {
         m_v += other.m_v;
         return (*this);
         }

      GFp1& operator-=(const GFp1& other)
         {
         m_v -= other.m_v;
         return (*this);
         }

      GFp1 operator*(const GFp1& other) const
         {
         return GFp1(m_v * other.m_v);
         }

      GFp1 operator*=(const GFp1& other)
         {
         m_v *= other.m_v;
         return (*this);
         }

      GFp1 square() const
         {
         secure_vector<word> ws;
         return m_v.square(ws);
         }

      GFp1 mul_2() const
         {
         secure_vector<word> ws;
         GFp1 x = *this;
         x.m_v.mul_by_2(ws);
         return x;
         }

      GFp1 mul_3() const
         {
         secure_vector<word> ws;
         GFp1 x = *this;
         x.m_v.mul_by_3(ws);
         return x;
         }

      GFp1 inverse() const
         {
         return m_v.multiplicative_inverse();
         }

      GFp1 additive_inverse() const
         {
         return m_v.additive_inverse();
         }

      std::string to_string() const
         {
         std::ostringstream oss;
         oss << value();
         return oss.str();
         }

   private:

      Montgomery_Int m_v;
   };

template<typename Field>
class Field_2 final
   {
   public:
      Field_2() :
         m_x(Field::zero()),
         m_y(Field::zero())
         {}

      Field_2(const Field& x, const Field& y) :
         m_x(x),
         m_y(y)
         {}

      Field_2(const uint8_t bits[]) :
         m_x(bits),
         m_y(bits + Field::size())
         {
         }

      static Field_2 one()
         {
         return Field_2(Field::zero(), Field::one());
         }

      static Field_2 zero()
         {
         return Field_2(Field::zero(), Field::zero());
         }

      static size_t size() { return Field::size() * 2; }

      const Field& x() const { return m_x; }
      const Field& y() const { return m_y; }

      bool operator==(const Field_2& other) const
         {
         return x() == other.x() && y() == other.y();
         }

      bool operator!=(const Field_2& other) const { return !(*this == other); }

      bool is_one() const { return x().is_zero() && y().is_one(); }
      bool is_zero() const { return x().is_zero() && y().is_zero(); }

      Field_2 operator+(const Field_2& other) const
         {
         return Field_2(x() + other.x(), y() + other.y());
         }

      Field_2& operator+=(const Field_2& other)
         {
         m_x += other.x();
         m_y += other.y();
         return (*this);
         }

      Field_2 operator-(const Field_2& other) const
         {
         return Field_2(x() - other.x(), y() - other.y());
         }

      Field_2& operator-=(const Field_2& other)
         {
         m_x -= other.x();
         m_y -= other.y();
         return (*this);
         }

      Field_2 negate() const
         {
         return Field_2(x().additive_inverse(), y().additive_inverse());
         }

      Field_2 mul_2() const
         {
         return Field_2(x().mul_2(), y().mul_2());
         }

      Field_2 operator*(const Field_2& other) const
         {
         const Field vy = (y() * other.y());
         const Field vx = (x() * other.x());
         const Field c0 = (vy - vx);
         const Field c1 = (x() + y())*(other.x() + other.y()) - (vy + vx);

         return Field_2(c1, c0);
         }

      Field_2 operator*=(const Field_2& other)
         {
         *this = (*this * other);
         return *this;
         }

      Field_2 operator*(const Field& scalar) const
         {
         return Field_2(x() * scalar, y() * scalar);
         }

      Field_2 square() const
         {
         // Complex squaring
         const Field ty = y().square() - x().square();
         const Field tx = (x() * y()).mul_2();
         return Field_2(tx, ty);
         }

      Field_2 mul_xi() const
         {
         // (xi + y)(3 + i) = 3xi + 3y - x + yi = (3x + y)i + (3y - x)
         const Field tx = x().mul_3() + y();
         const Field ty = y().mul_3() - x();
         return Field_2(tx, ty);
         }

      Field_2 inverse() const
         {
         // Algorithm 8 from http://eprint.iacr.org/2010/354.pdf
         const Field t = x().square() + y().square();

         const Field inv = t.inverse();

         const Field c_x = (x().additive_inverse() * inv);
         const Field c_y = (y() * inv);

         return Field_2(c_x, c_y);
         }

      Field_2 exp(const BigInt& k) const
         {
         Field_2 R[2] = { Field_2::one(), *this };

         const size_t k_bits = k.bits();

         for(size_t i = 0; i != k_bits; ++i)
            {
            const uint8_t kb = k.get_bit(k_bits - 1 - i);
            R[kb ^ 1] = R[kb] * R[kb ^ 1];
            R[kb] = R[kb].square();
            }
         return R[0];
         }

      Field_2 conjugate() const
         {
         return Field_2(x().additive_inverse(), y());
         }

      Field_2 mul_conjugate() const
         {
         return (*this) * conjugate();
         }

      std::string to_string() const
         {
         std::ostringstream oss;
         oss << "(" << x().value() << "," << y().value() << ")";
         return oss.str();
         }

      std::vector<uint8_t> serialize() const
         {
         std::vector<uint8_t> v;
         v.reserve(2 * Field::size());
         v += x().serialize();
         v += y().serialize();
         return v;
         }

   private:
      Field m_x, m_y;
   };


/*
Represented as i*x + y
*/
class GFp2 final
   {
   public:
      GFp2() : m_x(GFp1::zero()), m_y(GFp1::zero()) {}

      GFp2(const GFp1& x, const GFp1& y) :
         m_x(x), m_y(y) {}

      GFp2(const BigInt& x, const BigInt& y) :
         m_x(x), m_y(y) {}

      GFp2(const uint8_t bits[]) : m_x(bits), m_y(bits + GFp1::size())
         {
         }

      static GFp2 one()
         {
         return GFp2(GFp1::zero(), GFp1::one());
         }

      static GFp2 zero()
         {
         return GFp2(GFp1::zero(), GFp1::zero());
         }

      static const GFp2& curve_B()
         {
         // b' on the twist is b/xi
         static GFp2 curve_B = xi().inverse() * GFp2(GFp1::zero(), GFp1::curve_B());
         return curve_B;
         }

      static const GFp2& xi()
         {
         static GFp2 xi(GFp1::one(), GFp1(3));
         return xi;
         }

      static const std::vector<GFp2>& xi1()
         {
         static const std::vector<GFp2> xi1 = {
            xi().exp((1*(Params::p() - 1))/6),
            xi().exp((2*(Params::p() - 1))/6),
            xi().exp((3*(Params::p() - 1))/6),
            xi().exp((4*(Params::p() - 1))/6),
            xi().exp((5*(Params::p() - 1))/6)
         };

         return xi1;
         }

      static const std::vector<GFp2>& xi2()
         {
         static const std::vector<GFp2> xi2 = {
            xi1()[0] * xi1()[0].conjugate(),
            xi1()[1] * xi1()[1].conjugate(),
            xi1()[2] * xi1()[2].conjugate(),
            xi1()[3] * xi1()[3].conjugate(),
            xi1()[4] * xi1()[4].conjugate(),
         };

         return xi2;
         }

      static size_t size() { return GFp1::size() * 2; }

      const GFp1& x() const { return m_x; }
      const GFp1& y() const { return m_y; }

      bool operator==(const GFp2& other) const
         {
         return m_x == other.m_x && m_y == other.m_y;
         }

      bool operator!=(const GFp2& other) const { return !(*this == other); }

      bool is_one() const { return m_x.is_zero() && m_y.is_one(); }
      bool is_zero() const { return m_x.is_zero() && m_y.is_zero(); }

      GFp2 operator+(const GFp2& other) const
         {
         return GFp2(m_x + other.m_x, m_y + other.m_y);
         }

      GFp2& operator+=(const GFp2& other)
         {
         m_x += other.m_x;
         m_y += other.m_y;
         return (*this);
         }

      GFp2 operator-(const GFp2& other) const
         {
         return GFp2(m_x - other.m_x, m_y - other.m_y);
         }

      GFp2& operator-=(const GFp2& other)
         {
         m_x -= other.m_x;
         m_y -= other.m_y;
         return (*this);
         }

      GFp2 negate() const
         {
         return GFp2(m_x.additive_inverse(), m_y.additive_inverse());
         }

      GFp2 mul_2() const
         {
         return GFp2(m_x.mul_2(), m_y.mul_2());
         }

      GFp2 operator*(const GFp2& other) const
         {
         const GFp1 vy = (m_y * other.m_y);
         const GFp1 vx = (m_x * other.m_x);
         const GFp1 c0 = (vy - vx);
         const GFp1 c1 = (m_x + m_y)*(other.m_x + other.m_y) - (vy + vx);

         return GFp2(c1, c0);
         }

      GFp2 operator*=(const GFp2& other)
         {
         *this = (*this * other);
         return *this;
         }

      GFp2 operator*(const GFp1& scalar) const
         {
         return GFp2(m_x * scalar, m_y * scalar);
         }

      GFp2 square() const
         {
         // Complex squaring
         const GFp1 ty = m_y.square() - m_x.square();
         const GFp1 tx = (m_x * m_y).mul_2();
         return GFp2(tx, ty);
         }

      GFp2 mul_xi() const
         {
         // (xi + y)(3 + i) = 3xi + 3y - x + yi = (3x + y)i + (3y - x)
         const GFp1 tx = m_x.mul_3() + m_y;
         const GFp1 ty = m_y.mul_3() - m_x;
         return GFp2(tx, ty);
         }

      GFp2 inverse() const
         {
         // Algorithm 8 from http://eprint.iacr.org/2010/354.pdf
         const GFp1 t = m_x.square() + m_y.square();

         const GFp1 inv = t.inverse();

         const GFp1 c_x = (m_x.additive_inverse() * inv);
         const GFp1 c_y = (m_y * inv);

         return GFp2(c_x, c_y);
         }

      GFp2 exp(const BigInt& k) const
         {
         GFp2 R[2] = { GFp2::one(), *this };

         const size_t k_bits = k.bits();

         for(size_t i = 0; i != k_bits; ++i)
            {
            const uint8_t kb = k.get_bit(k_bits - 1 - i);
            R[kb ^ 1] = R[kb] * R[kb ^ 1];
            R[kb] = R[kb].square();
            }
         return R[0];
         }

      GFp2 conjugate() const
         {
         return GFp2(m_x.additive_inverse(), m_y);
         }

      GFp2 mul_conjugate() const
         {
         return (*this) * GFp2(m_x.additive_inverse(), m_y);
         }

      std::string to_string() const
         {
         std::ostringstream oss;
         oss << "(" << m_x.value() << "," << m_y.value() << ")";
         return oss.str();
         }

      std::vector<uint8_t> serialize() const
         {
         std::vector<uint8_t> v;
         v.reserve(2 * 32);
         v += x().serialize();
         v += y().serialize();
         return v;
         }

   private:
      GFp1 m_x, m_y;
   };

class GFp6 final
   {
   public:
      GFp6(const GFp2& x, const GFp2& y, const GFp2& z) :
         m_x(x), m_y(y), m_z(z)
         {}

      GFp6(const uint8_t bits[]) :
         m_x(bits),
         m_y(bits + GFp2::size()),
         m_z(bits + GFp2::size() * 2)
         {
         }

      static GFp6 one()
         {
         return GFp6(GFp2::zero(), GFp2::zero(), GFp2::one());
         }

      static GFp6 zero()
         {
         return GFp6(GFp2::zero(), GFp2::zero(), GFp2::zero());
         }

      static size_t size() { return GFp2::size() * 3; }

      const GFp2& x() const { return m_x; }
      const GFp2& y() const { return m_y; }
      const GFp2& z() const { return m_z; }

      bool operator==(const GFp6& other) const
         {
         return x() == other.x() && y() == other.y() && z() == other.z();
         }

      bool operator!=(const GFp6& other) const
         {
         return !(*this == other);
         }

      bool is_zero() const
         {
         return x().is_zero() && y().is_zero() && z().is_zero();
         }

      bool is_one() const
         {
         return x().is_zero() && y().is_zero() && z().is_one();
         }

      GFp6 negate() const
         {
         return GFp6(x().negate(), y().negate(), z().negate());
         }

      GFp6 operator+(const GFp6& other) const
         {
         return GFp6(x() + other.x(),
                     y() + other.y(),
                     z() + other.z());
         }

      GFp6 operator-(const GFp6& other) const
         {
         return GFp6(x() - other.x(),
                     y() - other.y(),
                     z() - other.z());
         }

      GFp6& operator+=(const GFp6& other)
         {
         m_x += other.x();
         m_y += other.y();
         m_z += other.z();
         return (*this);
         }

      GFp6& operator-=(const GFp6& other)
         {
         m_x -= other.x();
         m_y -= other.y();
         m_z -= other.z();
         return (*this);
         }

      GFp6 mul_2() const
         {
         return GFp6(x().mul_2(), y().mul_2(), z().mul_2());
         }

      GFp6 operator*(const GFp2& b) const
         {
         return GFp6(x() * b, y() * b, z() * b);
         }

      GFp6 operator*(const GFp6& other) const
         {
         // Algorithm 13 from http://eprint.iacr.org/2010/354.pdf

         GFp2 t0, t1, t2, tx, ty, tz;

         t0 = (z() * other.z());
         t1 = (y() * other.y());
         t2 = (x() * other.x());

         tz = (x() + y()) * (other.x() + other.y());
         tz -= t1;
         tz -= t2;
         tz = tz.mul_xi();
         tz += t0;

         ty = (y() + z()) * (other.y() + other.z());
         ty -= t0;
         ty -= t1;
         ty += t2.mul_xi();

         tx = (x() + z()) * (other.x() + other.z());
         tx -= t0;
         tx += t1;
         tx -= t2;

         return GFp6(tx, ty, tz);
         }

      GFp6 square() const
         {
         // Algorithm 16 from https://eprint.iacr.org/2010/354.pdf
         GFp2 ay2 = y().mul_2();
         GFp2 c4 = (z() * ay2);
         GFp2 c5 = x().square();
         GFp2 c1 = c5.mul_xi() + c4;
         GFp2 c2 = c4 - c5;
         GFp2 c3 = z().square();
         c4 = x() + z() - y();
         c5 = (ay2 * x());
         c4 = c4.square();
         GFp2 c0 = c5.mul_xi() + c3;
         c2 = c2 + c4 + c5 - c3;
         return GFp6(c2, c1, c0);
         }

      GFp6 mul_tau() const
         {
         return GFp6(y(), z(), x().mul_xi());
         }

      GFp6 inverse() const
         {
         // Algorithm 17 from https://eprint.iacr.org/2010/354.pdf

         const GFp2 XX = x().square();
         const GFp2 YY = y().square();
         const GFp2 ZZ = z().square();

         const GFp2 XY = (x() * y());
         const GFp2 XZ = (x() * z());
         const GFp2 YZ = (y() * z());

         const GFp2 A = ZZ - XY.mul_xi();
         const GFp2 B = XX.mul_xi() - YZ;
         // There is an error in the paper for this line
         const GFp2 C = YY - XZ;

         GFp2 F = (C * y()).mul_xi();
         F += (A * z());
         F += (B * x()).mul_xi();

         F = F.inverse();

         return GFp6(C * F, B * F, A * F);
         }

      std::vector<uint8_t> serialize() const
         {
         std::vector<uint8_t> v;
         v.reserve(6 * 32);
         v += x().serialize();
         v += y().serialize();
         v += z().serialize();
         return v;
         }

      std::string to_string() const
         {
         std::ostringstream out;
         out << "(" << x().to_string() << "," << y().to_string() << "," << z().to_string() << ")";
         return out.str();
         }

   private:
      GFp2 m_x, m_y, m_z;
   };

class GFp12 final
   {
   public:
      GFp12() : m_x(GFp6::zero()), m_y(GFp6::zero()) {}

      GFp12(const GFp6& x, const GFp6& y) :
         m_x(x), m_y(y) {}

      GFp12(const uint8_t bits[]) :
         m_x(bits),
         m_y(bits + GFp6::size())
         {
         throw Not_Implemented("GFp12 decoding");
         }

      static GFp12 one()
         {
         return GFp12(GFp6::zero(), GFp6::one());
         }

      static GFp12 zero()
         {
         return GFp12(GFp6::zero(), GFp6::zero());
         }

      static size_t size() { return GFp6::size() * 2; }

      const GFp6& x() const { return m_x; }
      const GFp6& y() const { return m_y; }

      bool operator==(const GFp12& other) const
         {
         return x() == other.x() && y() == other.y();
         }

      bool operator!=(const GFp12& other) const
         {
         return !(*this == other);
         }

      bool is_zero() const
         {
         return x().is_zero() && y().is_zero();
         }

      bool is_one() const
         {
         return x().is_zero() && y().is_one();
         }

      GFp12 conjugate() const
         {
         return GFp12(x().negate(), y());
         }

      GFp12 negate() const
         {
         return GFp12(x().negate(), y().negate());
         }

      GFp12 operator-(const GFp12& other) const
         {
         return GFp12(x() - other.x(), y() - other.y());
         }

      GFp12 operator*(const GFp12& other) const
         {
         // TODO use Karatsuba
         const GFp6 AXBX = x() * other.x();
         const GFp6 AXBY = x() * other.y();
         const GFp6 AYBX = y() * other.x();
         const GFp6 AYBY = y() * other.y();
         return GFp12(AXBY + AYBX, AYBY + AXBX.mul_tau());
         }

      GFp12 operator*(const GFp6& k) const
         {
         return GFp12(x() * k, y() * k);
         }

      GFp12 exp(const BigInt& k) const
         {
         GFp12 R[2] = { GFp12::one(), *this };

         const size_t k_bits = k.bits();

         for(size_t i = 0; i != k_bits; ++i)
            {
            const uint8_t kb = k.get_bit(k_bits - 1 - i);
            R[kb ^ 1] = R[kb] * R[kb ^ 1];
            R[kb] = R[kb].square();
            }
         return R[0];
         }

      GFp12 square() const
         {
         // Seems like this could be made simpler

         const GFp6 v0 = x() * y();
         GFp6 ty = (x() + y()) * (x().mul_tau() + y());

         ty -= v0;
         ty -= v0.mul_tau();

         return GFp12(v0.mul_2(), ty);
         }

      GFp12 inverse() const
         {
         const GFp12 e = conjugate();

         // TODO clean this up
         GFp6 t1 = x().square();
         GFp6 t2 = y().square();
         t1 = t1.mul_tau();
         t1 = t2 - t1;
         t2 = t1.inverse();

         return e * t2;
         }

      GFp12 frobenius() const
         {
         const std::vector<GFp2>& xi1 = GFp2::xi1();

         GFp2 e1_x = x().x().conjugate() * xi1[4];
         GFp2 e1_y = x().y().conjugate() * xi1[2];
         GFp2 e1_z = x().z().conjugate() * xi1[0];

         GFp2 e2_x = y().x().conjugate() * xi1[3];
         GFp2 e2_y = y().y().conjugate() * xi1[1];
         GFp2 e2_z = y().z().conjugate();

         return GFp12(GFp6(e1_x, e1_y, e1_z),
                      GFp6(e2_x, e2_y, e2_z));
         }

      GFp12 frobenius_p2() const
         {
         const std::vector<GFp2>& xi2 = GFp2::xi2();
         GFp2 e1_x = x().x() * xi2[4];
         GFp2 e1_y = x().y() * xi2[2];
         GFp2 e1_z = x().z() * xi2[0];

         GFp2 e2_x = y().x() * xi2[3];
         GFp2 e2_y = y().y() * xi2[1];
         GFp2 e2_z = y().z();

         return GFp12(GFp6(e1_x, e1_y, e1_z),
                      GFp6(e2_x, e2_y, e2_z));
         }

      std::vector<uint8_t> serialize() const
         {
         std::vector<uint8_t> v;
         v.reserve(12 * 32);
         v += x().serialize();
         v += y().serialize();
         return v;
         }

      std::string to_string() const
         {
         std::ostringstream out;
         out << "(" << x().to_string() << "," << y().to_string() << ")";
         return out.str();
         }

   private:
      GFp6 m_x, m_y;
   };

template<typename Field>
class CurvePoint final
   {
   public:
      CurvePoint() : m_x(Field::zero()), m_y(Field::zero()), m_z(Field::zero()) {}

      CurvePoint(const Field& x, const Field& y, const Field& z = Field::one()) :
         m_x(x), m_y(y), m_z(z) {}

      CurvePoint(const uint8_t bits[]) :
         m_x(bits),
         m_y(bits + Field::size()),
         m_z(Field::one())
         {
         }

      static size_t size() { return Field::size() * 2; }

      Field zero() const { return Field::zero(); }
      Field one() const { return Field::one(); }

      const Field& x() const { return m_x; }
      const Field& y() const { return m_y; }
      const Field& z() const { return m_z; }

      std::vector<uint8_t> serialize() const
         {
         this->force_affine();

         std::vector<uint8_t> v;

         // TODO point compression
         v += x().serialize();
         v += y().serialize();

         return v;
         }

      void force_affine() const
         {
         if(z().is_one())
            return;

         const Field zinv = z().inverse();
         const Field zinv2 = (zinv * zinv);
         const Field zinv3 = (zinv2 * zinv);

         m_x *= zinv2;
         m_y *= zinv3;
         m_z = Field::one();
         }

      bool operator==(const CurvePoint& other) const
         {
         this->force_affine();
         other.force_affine();

         return (x() == other.x() && y() == other.y());
         }

      bool is_on_curve(const Field& b) const
         {
         this->force_affine();

         Field yy = y().square();

         const Field xxx = x().square() * x();
         yy -= xxx;
         yy -= b;
         return yy.is_zero();
         }

      bool is_infinite() const
         {
         return z().is_zero();
         }

      CurvePoint pt_add(const CurvePoint& b) const
         {
         if(is_infinite())
            return b;

         if(b.is_infinite())
            return (*this);

         /*
         http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
         Z1Z1 = a.z^2
         Z2Z2 = b.z^2
         U1 = a.x*Z2Z2
         U2 = b.x*Z1Z1
         S1 = a.y*b.z*Z2Z2
         S2 = b.y*a.z*Z1Z1
         H = U2-U1
         I = (2*H)^2
         J = H*I
         r = 2*(S2-S1)
         V = U1*I
         X3 = r^2-J-2*V
         Y3 = r*(V-X3)-2*S1*J
         Z3 = ((a.z+b.z)^2-Z1Z1-Z2Z2)*H
         */

         Field z1z1 = z().square();
         Field z2z2 = b.z().square();
         Field u1 = (z2z2 * x());
         Field u2 = (z1z1 * b.x());
         Field h = u2 - u1;

         Field s1 = (y() * b.z() * z2z2);
         Field s2 = (b.y() * z() * z1z1);
         Field r = s2 - s1;

         // Not constant time :(
         if(h.is_zero() && r.is_zero())
            return pt_double();

         r = r.mul_2();
         Field i = h.square();
         i = i.mul_2().mul_2();
         Field j = (h * i);

         Field V = (u1 * i);

         Field c_x = (r.square() - j - V.mul_2());
         Field c_y = (r * (V - c_x) - s1*j.mul_2());

         Field c_z = z() + b.z();
         c_z = c_z.square();
         c_z -= z1z1;
         c_z -= z2z2;
         c_z = c_z * h;

         return CurvePoint(c_x, c_y, c_z);
         }

      CurvePoint pt_double() const
         {
         // http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l

         const Field A = x().square();
         const Field B = y().square();
         const Field C = B.square();

         Field t = x() + B;
         t = t.square();

         Field D = (t - A - C);
         D = D.mul_2();

         const Field E = A.mul_2() + A;
         const Field F = E.square();

         const Field C8 = C.mul_2().mul_2().mul_2();

         const Field c_x = (F - D.mul_2());
         const Field c_y = (E * (D - c_x) - C8);
         const Field c_z = (y() * z()).mul_2();

         return CurvePoint(c_x, c_y, c_z);
         }

      CurvePoint scalar_mul(const BigInt& k) const
         {
         CurvePoint R[2] = { CurvePoint(Field::zero(), Field::zero(), Field::zero()), *this };

         const size_t k_bits = k.bits();

         for(size_t i = 0; i != k_bits; ++i)
            {
            const uint8_t kb = k.get_bit(k_bits - 1 - i);
            R[kb ^ 1] = R[kb].pt_add(R[kb ^ 1]);
            R[kb] = R[kb].pt_double();
            }
         return R[0];
         }

      CurvePoint negate() const
         {
         return CurvePoint(x(), y().negate(), z());
         }

      std::string to_string() const
         {
         //force_affine();
         std::ostringstream out;
         //out << "(" << x().to_string() << "," << y().to_string() << ")";
         out << "(" << x().to_string() << "," << y().to_string() << "," << z().to_string() << ")";
         return out.str();
         }

   private:
      // mutable for force_affine
      mutable Field m_x, m_y, m_z;
   };


GFp12 mul_line(const GFp12& r, const GFp2& a, const GFp2& b, const GFp2& c)
   {
   // See function fp12e_mul_line in dclxvi

   GFp6 t1(GFp2::zero(), a, b);
   GFp6 t2(GFp2::zero(), a, b + c);

   GFp6 r_x = r.x();
   GFp6 r_y = r.y();

   t1 = t1 * r_x;
   GFp6 t3 = r_y * c;
   r_x += r_y;
   r_y = t3;
   r_x = r_x * t2;
   r_x -= t1;
   r_x -= r_y;
   r_y += t1.mul_tau();

   return GFp12(r_x, r_y);
   }

void line_func_add(GFp12& f,
                   CurvePoint<GFp2>& r,
                   const CurvePoint<GFp2>& p,
                   const CurvePoint<GFp1>& q,
                   const GFp2& r2)
   {
   GFp2 r_t = r.z().square();
   GFp2 B = p.x() * r_t;
   GFp2 D = p.y() + r.z();
   D = D.square();
   D -= r2;
   D -= r_t;
   D *= r_t;

   GFp2 H = B - r.x();
   GFp2 I = H.square();

   GFp2 E = I.mul_2().mul_2();

   GFp2 J = H * E;
   GFp2 L1 = D - r.y();
   L1 -= r.y();

   GFp2 V = r.x() * E;

   GFp2 r_x = L1.square();
   r_x -= J;
   r_x -= V.mul_2();

   GFp2 r_z = r.z() + H;
   r_z = r_z.square();
   r_z -= r_t;
   r_z -= I;

   GFp2 t = V - r_x;
   t *= L1;
   GFp2 t2 = r.y() * J;
   t2 = t2.mul_2();
   GFp2 r_y = t - t2;

   CurvePoint<GFp2> r_out = CurvePoint<GFp2>(r_x, r_y, r_z);

   t = p.y() + r_z;
   t = t.square();
   t = t - r2;
   t = t - r_z.square();

   t2 = L1 * p.x();
   t2 = t2.mul_2();
   GFp2 a = t2 - t;

   GFp2 c = r_z.mul_2() * q.y();

   GFp2 b = L1.negate();
   //b = b.mul_scalar(q.x).mul_2();
   b = b.mul_2() * q.x();

   r = r_out;
   f = mul_line(f, a, b, c);
   }

void line_func_double(GFp12& f,
                      CurvePoint<GFp2>& r,
                      const CurvePoint<GFp1>& q)
   {
   GFp2 r_t = r.z().square();

   GFp2 A = r.x().square();
   GFp2 B = r.y().square();
   GFp2 C = B.square();

   GFp2 D = r.x() + B;
   D = D.square();
   D -= A;
   D -= C;
   D = D.mul_2();

   GFp2 E = A.mul_2() + A;
   GFp2 F = E.square();

   GFp2 C8 = C.mul_2().mul_2().mul_2();

   GFp2 r_x = F - D.mul_2();
   GFp2 r_y = E * (D - r_x) - C8;

   // (y+z)*(y+z) - (y*y) - (z*z) = 2*y*z
   GFp2 r_z = (r.y() + r.z()).square() - B - r_t;

   CurvePoint<GFp2> r_out = CurvePoint<GFp2>(r_x, r_y, r_z);

   GFp2 a = r.x() + E;
   a = a.square();
   a -= (A + F + B.mul_2().mul_2());

   GFp2 t = E * r_t;
   t = t.mul_2();
   GFp2 b = t.negate();
   b = b * q.x();

   GFp2 c = r_z * r_t;
   c = c.mul_2() * q.y();

   r = r_out;
   f = mul_line(f, a, b, c);

   /*
   std::cout << "a = " << a.to_string() << " b = " << b.to_string() << " c = " << c.to_string() <<
      "\nret = " << f.to_string() << "\nnewR = " << r.to_string() << "\n";
   */
   }

GFp12 miller_loop(const CurvePoint<GFp1>& p,
                  const CurvePoint<GFp2>& q)
   {
   const CurvePoint<GFp2> Q = q;
   const CurvePoint<GFp1> P = p;

   Q.force_affine();
   P.force_affine();

   //std::cout << "P = " << P.to_string() << "\n";
   //std::cout << "Q = " << Q.to_string() << "\n";

   const CurvePoint<GFp2> mQ = Q.negate();

   //std::cout << "mQ = " << mQ.to_string() << "\n";
   GFp12 f(GFp6::zero(), GFp6::one());
   CurvePoint<GFp2> T = Q;

   const GFp2 Qp = Q.y().square();

   // non-adjacent form encoding of 6*u + 2
   // TODO pass as param
   static const int8_t naf_6u_plus_2[] = {
      0, 0, 0, 1, 0, 0, 0, 0, -1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0,
      -1, 0, 0, 0, -1, 0, 1, 0, 0, 0, 1, 0, -1, 0, 0, 0, 1, 0, 1, 0,
      0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1,
      0, 0, 0
   };

   for(int8_t bit : naf_6u_plus_2)
      {
      //std::cout << "Before loop bit " << static_cast<int>(bit) << " ret = " << f.to_string() << "\n";

      // TODO skip on first iteration
      f = f.square();

      line_func_double(f, T, P);
      //std::cout << "double " << f.to_string() << "\n";

      if(bit == 1)
         {
         line_func_add(f, T, Q, P, Qp);
         }
      else if(bit == -1)
         {
         line_func_add(f, T, mQ, P, Qp);
         }
      }

   //std::cout << "End of miller " << f.to_string() << "\n";

   // Q1 = pi(Q)
   CurvePoint<GFp2> Q1(Q.x().conjugate() * GFp2::xi1()[1],
                       Q.y().conjugate() * GFp2::xi1()[2]);

   // Q2 = pi2(Q)
   CurvePoint<GFp2> Q2(Q.x() * GFp2::xi2()[1], Q.y());

   line_func_add(f, T, Q1, P, Q1.y().square());
   line_func_add(f, T, Q2, P, Q2.y().square());

   return f;
   }

GFp12 final_exp(const GFp12& inp)
   {
   const uint64_t u = 0x5A76AE9AEC588301; // TODO pass as param?

   // Algorithm 31 from https://eprint.iacr.org/2010/354.pdf

   GFp12 t1 = inp.conjugate();
   GFp12 inv = inp.inverse();

   t1 = t1 * inv;
   // Now t1 = inp^(p**6-1)

   GFp12 t2 = t1.frobenius_p2();
   t1 = t1 * t2;

   GFp12 fp1 = t1.frobenius();
   GFp12 fp2 = t1.frobenius_p2();
   GFp12 fp3 = fp2.frobenius();

   GFp12 fu1 = t1.exp(u);
   GFp12 fu2 = fu1.exp(u);
   GFp12 fu3 = fu2.exp(u);

   GFp12 y3 = fu1.frobenius();
   GFp12 fu2p = fu2.frobenius();
   GFp12 fu3p = fu3.frobenius();
   GFp12 y2 = fu2.frobenius_p2();

   GFp12 y0 = fp1 * fp2;
   y0 = y0 * fp3;

   GFp12 y1 = t1.conjugate();
   GFp12 y5 = fu2.conjugate();
   y3 = y3.conjugate();
   GFp12 y4 = fu1 * fu2p;
   y4 = y4.conjugate();

   GFp12 y6 = fu3 * fu3p;
   y6 = y6.conjugate();

   GFp12 t0 = y6.square();
   t0 = t0 * y4;
   t0 = t0 * y5;

   t1 = y3 * y5;
   t1 = t1 * t0;
   t0 = t0 * y2;
   t1 = t1.square();
   t1 = t1 * t0;
   t1 = t1.square();
   t0 = t1 * y1;
   t1 = t1 * y0;
   t0 = t0.square();
   t0 = t0 * t1;

   return t0;
   }

GFp12 optimal_ate(const CurvePoint<GFp2>& a,
                  const CurvePoint<GFp1>& b)
   {
   const GFp12 optate = miller_loop(b, a);

   //std::cout << "Miller " << hex_encode(optate.serialize()) << "\n";
   GFp12 e = final_exp(optate);
   //std::cout << "FinalE " << hex_encode(e.serialize()) << "\n";

   if(a.is_infinite() || b.is_infinite())
      return GFp12(GFp6::zero(), GFp6::one());

   return e;
   }

const CurvePoint<GFp1>& g1_generator()
   {
   // Any point (1,y) where y is a square root of b+1 is a generator
   static const CurvePoint<GFp1> g1_gen(GFp1::one(), GFp1(Params::p() - 2));
   return g1_gen;
   }

const CurvePoint<GFp2>& g2_generator()
   {
   /*
   * This is related to the G1 generator, unfortunately (per email with dclxvi authors),
   * the exact derivation is lost.
   */
   static const CurvePoint<GFp2> g2_gen(
      GFp2(BigInt("0x2ecca446ff6f3d4d03c76e9b5c752f28bc37b364cb05ac4a37eb32e1c3245970"),
           BigInt("0x8f25386f72c9462b81597d65ae2092c4b97792155dcdaad32b8a6dd41792534c")),
      GFp2(BigInt("0x2db10ef5233b0fe3962b9ee6a4bbc2b5bde01a54f3513d42df972e128f31bf12"),
           BigInt("0x274e5747e8cafacc3716cc8699db79b22f0e4ff3c23e898f694420a3be3087a5")));

   return g2_gen;
   }

}

}

class BN_256_G1_Data final
   {
   public:
      BN_256_G1_Data(const uint8_t bits[]) : m_g1(bits) {}
      BN_256_G1_Data(const BN_256_Impl::CurvePoint<BN_256_Impl::GFp1>& g1) : m_g1(g1) {}

      const BN_256_Impl::CurvePoint<BN_256_Impl::GFp1>& g1() const { return m_g1; }

   private:
      BN_256_Impl::CurvePoint<BN_256_Impl::GFp1> m_g1;
   };

class BN_256_G2_Data final
   {
   public:
      BN_256_G2_Data(const uint8_t bits[]) : m_g2(bits) {}
      BN_256_G2_Data(const BN_256_Impl::CurvePoint<BN_256_Impl::GFp2>& g2) : m_g2(g2) {}
      const BN_256_Impl::CurvePoint<BN_256_Impl::GFp2>& g2() const { return m_g2; }
   private:
      BN_256_Impl::CurvePoint<BN_256_Impl::GFp2> m_g2;
   };

class BN_256_GT_Data final
   {
   public:
      BN_256_GT_Data(const uint8_t bits[]) : m_gt(bits) {}
      BN_256_GT_Data(const BN_256_Impl::GFp12& gt) : m_gt(gt) {}
      const BN_256_Impl::GFp12& gt() const { return m_gt; }
   private:
      BN_256_Impl::GFp12 m_gt;
   };


BN_256::G1::G1(std::shared_ptr<BN_256_G1_Data> data) : m_data(data) {}

std::vector<uint8_t> BN_256::G1::serialize() const
   {
   return m_data->g1().serialize();
   }

bool BN_256::G1::operator==(const G1& other) const
   {
   return m_data->g1() == other.m_data->g1();
   }

BN_256::G1 BN_256::G1::operator*(const BigInt& k) const
   {
   auto r = m_data->g1().scalar_mul(k);
   return BN_256::G1(std::make_shared<BN_256_G1_Data>(r));
   }

BN_256::G1 BN_256::G1::operator+(const BN_256::G1& x) const
   {
   auto r = m_data->g1().pt_add(x.m_data->g1());
   return BN_256::G1(std::make_shared<BN_256_G1_Data>(r));
   }

bool BN_256::G1::valid_element() const
   {
   return m_data->g1().is_on_curve(BN_256_Impl::GFp1::curve_B());
   }

BN_256::G2::G2(std::shared_ptr<BN_256_G2_Data> data) : m_data(data) {}

std::vector<uint8_t> BN_256::G2::serialize() const
   {
   return m_data->g2().serialize();
   }

bool BN_256::G2::operator==(const G2& other) const
   {
   return m_data->g2() == other.m_data->g2();
   }

BN_256::G2 BN_256::G2::operator*(const BigInt& k) const
   {
   auto r = m_data->g2().scalar_mul(k);
   return BN_256::G2(std::make_shared<BN_256_G2_Data>(r));
   }

BN_256::G2 BN_256::G2::operator+(const BN_256::G2& x) const
   {
   auto r = m_data->g2().pt_add(x.m_data->g2());
   return BN_256::G2(std::make_shared<BN_256_G2_Data>(r));
   }

bool BN_256::G2::valid_element() const
   {
   return m_data->g2().is_on_curve(BN_256_Impl::GFp2::curve_B());
   }

BN_256::GT::GT(std::shared_ptr<BN_256_GT_Data> data) : m_data(data) {}

std::vector<uint8_t> BN_256::GT::serialize() const
   {
   return m_data->gt().serialize();
   }

bool BN_256::GT::operator==(const GT& other) const
   {
   return m_data->gt() == other.m_data->gt();
   }

BN_256::GT BN_256::GT::operator*(const BigInt& k) const
   {
   auto r = m_data->gt().exp(k);
   return BN_256::GT(std::make_shared<BN_256_GT_Data>(r));
   }

BN_256::GT BN_256::GT::operator+(const BN_256::GT& x) const
   {
   auto r = m_data->gt() * x.m_data->gt();
   return BN_256::GT(std::make_shared<BN_256_GT_Data>(r));
   }

bool BN_256::GT::valid_element() const
   {
   // this doesn't seem right, not all elements are possible outputs of the pairing;
   // check for correct order?
   return true;
   }

BN_256::BN_256() :
   m_g1_generator(std::make_shared<BN_256_G1_Data>(BN_256_Impl::g1_generator())),
   m_g2_generator(std::make_shared<BN_256_G2_Data>(BN_256_Impl::g2_generator()))
   {
   }

BN_256::G1 BN_256::g1_generator() const
   {
   return m_g1_generator;
   }

BN_256::G2 BN_256::g2_generator() const
   {
   return m_g2_generator;
   }

const BigInt& BN_256::order() const
   {
   static const BigInt order("0x0x8fb501e34aa387f9aa6fecb86184dc22ae29838f49403218168a647d6464ba6d");
   return order;
   }

BN_256::GT BN_256::pairing(const BN_256::G1& g1, const BN_256::G2& g2) const
   {
   auto r = optimal_ate(g2.m_data->g2(), g1.m_data->g1());
   return BN_256::GT(std::make_shared<BN_256_GT_Data>(r));
   }

#if 0
BN_256::G1 BN_256::g1_hash(const uint8_t input[], size_t input_len) const
   {
   throw Not_Implemented("BN_256::g1_hash");
   }

BN_256::G2 BN_256::g2_hash(const uint8_t input[], size_t input_len) const
   {
   throw Not_Implemented("BN_256::g2_hash");
   }
#endif

BN_256::G1 BN_256::g1_deserialize(const uint8_t input[], size_t input_len) const
   {
   if(input_len != BN_256_Impl::CurvePoint<BN_256_Impl::GFp1>::size())
      throw Decoding_Error("Invalid length for BN-256 G1 input");
   return BN_256::G1(std::make_shared<BN_256_G1_Data>(input));
   }

BN_256::G2 BN_256::g2_deserialize(const uint8_t input[], size_t input_len) const
   {
   if(input_len != BN_256_Impl::CurvePoint<BN_256_Impl::GFp2>::size())
      throw Decoding_Error("Invalid length for BN-256 G2 input");
   return BN_256::G2(std::make_shared<BN_256_G2_Data>(input));
   }

}
