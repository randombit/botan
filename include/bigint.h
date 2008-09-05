/*************************************************
* BigInt Header File                             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_BIGINT_H__
#define BOTAN_BIGINT_H__

#include <botan/rng.h>
#include <botan/secmem.h>
#include <botan/mp_types.h>
#include <iosfwd>

namespace Botan {

/*************************************************
* BigInt                                         *
*************************************************/
class BOTAN_DLL BigInt
   {
   public:
      enum Base { Octal = 8, Decimal = 10, Hexadecimal = 16, Binary = 256 };
      enum Sign { Negative = 0, Positive = 1 };
      enum NumberType { Power2 };

      struct DivideByZero : public Exception
         { DivideByZero() : Exception("BigInt divide by zero") {} };

      BigInt& operator+=(const BigInt&);
      BigInt& operator-=(const BigInt&);

      BigInt& operator*=(const BigInt&);
      BigInt& operator/=(const BigInt&);
      BigInt& operator%=(const BigInt&);
      word    operator%=(word);
      BigInt& operator<<=(u32bit);
      BigInt& operator>>=(u32bit);

      BigInt& operator++() { return (*this += 1); }
      BigInt& operator--() { return (*this -= 1); }
      BigInt  operator++(int) { BigInt x = (*this); ++(*this); return x; }
      BigInt  operator--(int) { BigInt x = (*this); --(*this); return x; }

      BigInt operator-() const;
      bool operator !() const { return (!is_nonzero()); }

      s32bit cmp(const BigInt&, bool = true) const;
      bool is_even() const { return (get_bit(0) == 0); }
      bool is_odd()  const { return (get_bit(0) == 1); }
      bool is_nonzero() const { return (!is_zero()); }
      bool is_zero() const;

      void set_bit(u32bit);
      void clear_bit(u32bit);
      void mask_bits(u32bit);

      bool get_bit(u32bit) const;
      u32bit get_substring(u32bit, u32bit) const;
      byte byte_at(u32bit) const;

      // same as operator[], remove this
      word word_at(u32bit n) const
         { return ((n < size()) ? get_reg()[n] : 0); }

      u32bit to_u32bit() const;

      bool is_negative() const { return (sign() == Negative); }
      bool is_positive() const { return (sign() == Positive); }
      Sign sign() const { return (signedness); }
      Sign reverse_sign() const;
      void flip_sign();
      void set_sign(Sign);
      BigInt abs() const;

      u32bit size() const { return get_reg().size(); }
      u32bit sig_words() const;
      u32bit bytes() const;
      u32bit bits() const;

      const word* data() const { return get_reg().begin(); }
      SecureVector<word>& get_reg() { return rep.get_reg(); }
      const SecureVector<word>& get_reg() const { return rep.get_reg(); }
      void grow_reg(u32bit) const;
      void grow_to(u32bit) const;

      word& operator[](u32bit);
      word operator[](u32bit) const;
      void clear() { get_reg().clear(); }

      void randomize(RandomNumberGenerator& rng, u32bit n);

      void binary_encode(byte[]) const;
      void binary_decode(const byte[], u32bit);
      void binary_decode(const MemoryRegion<byte>&);
      u32bit encoded_size(Base = Binary) const;

      static SecureVector<byte> encode(const BigInt&, Base = Binary);
      static void encode(byte[], const BigInt&, Base = Binary);
      static BigInt decode(const byte[], u32bit, Base = Binary);
      static BigInt decode(const MemoryRegion<byte>&, Base = Binary);
      static SecureVector<byte> encode_1363(const BigInt&, u32bit);

      void swap(BigInt&);

      BigInt() { signedness = Positive; }
      BigInt(u64bit);
      BigInt(const BigInt&);
      BigInt(const std::string&);
      BigInt(const byte[], u32bit, Base = Binary);
      BigInt(RandomNumberGenerator& rng, u32bit bits);
      BigInt(Sign, u32bit);
      BigInt(NumberType, u32bit);
   private:
      class Rep
         {
         public:
            SecureVector<word>& get_reg()
               { sig = INVALID_SIG_WORD; return reg; }

            word& operator[](u32bit);
            word operator[](u32bit) const;

            const SecureVector<word>& get_reg() const { return reg; }

            u32bit sig_words() const;

            void swap(Rep& other)
               {
               std::swap(reg, other.reg);
               std::swap(sig, other.sig);
               }

            Rep() { sig = INVALID_SIG_WORD; }
         private:
            static const u32bit INVALID_SIG_WORD = 0xFFFFFFFF;
            mutable u32bit sig;
            SecureVector<word> reg;
         };

      Rep rep;
      Sign signedness;
   };

/*************************************************
* Arithmetic Operators                           *
*************************************************/
BigInt BOTAN_DLL operator+(const BigInt&, const BigInt&);
BigInt BOTAN_DLL operator-(const BigInt&, const BigInt&);
BigInt BOTAN_DLL operator*(const BigInt&, const BigInt&);
BigInt BOTAN_DLL operator/(const BigInt&, const BigInt&);
BigInt BOTAN_DLL operator%(const BigInt&, const BigInt&);
word   BOTAN_DLL operator%(const BigInt&, word);
BigInt BOTAN_DLL operator<<(const BigInt&, u32bit);
BigInt BOTAN_DLL operator>>(const BigInt&, u32bit);

/*************************************************
* Comparison Operators                           *
*************************************************/
inline bool operator==(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) == 0); }
inline bool operator!=(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) != 0); }
inline bool operator<=(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) <= 0); }
inline bool operator>=(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) >= 0); }
inline bool operator<(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) < 0); }
inline bool operator>(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) > 0); }

/*************************************************
* I/O Operators                                  *
*************************************************/
BOTAN_DLL std::ostream& operator<<(std::ostream&, const BigInt&);
BOTAN_DLL std::istream& operator>>(std::istream&, BigInt&);

}

namespace std {

inline void swap(Botan::BigInt& a, Botan::BigInt& b) { a.swap(b); }

}

#endif
