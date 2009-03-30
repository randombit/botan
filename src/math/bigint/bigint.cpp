/*
* BigInt Base
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/bigint.h>
#include <botan/mp_core.h>
#include <botan/loadstor.h>
#include <botan/parsing.h>
#include <botan/util.h>

namespace Botan {

/*
* Construct a BigInt from a regular number
*/
BigInt::BigInt(u64bit n)
   {
   set_sign(Positive);

   if(n == 0)
      return;

   const u32bit limbs_needed = sizeof(u64bit) / sizeof(word);

   reg.create(4*limbs_needed);
   for(u32bit j = 0; j != limbs_needed; ++j)
      reg[j] = ((n >> (j*MP_WORD_BITS)) & MP_WORD_MASK);
   }

/*
* Construct a BigInt of the specified size
*/
BigInt::BigInt(Sign s, u32bit size)
   {
   reg.create(round_up(size, 8));
   signedness = s;
   }

/*
* Construct a BigInt from a "raw" BigInt
*/
BigInt::BigInt(const BigInt& b)
   {
   const u32bit b_words = b.sig_words();

   if(b_words)
      {
      reg.create(round_up(b_words, 8));
      reg.copy(b.data(), b_words);
      set_sign(b.sign());
      }
   else
      {
      reg.create(2);
      set_sign(Positive);
      }
   }

/*
* Construct a BigInt from a string
*/
BigInt::BigInt(const std::string& str)
   {
   Base base = Decimal;
   u32bit markers = 0;
   bool negative = false;
   if(str.length() > 0 && str[0] == '-') { markers += 1; negative = true; }

   if(str.length() > markers + 2 && str[markers    ] == '0' &&
                                    str[markers + 1] == 'x')
      { markers += 2; base = Hexadecimal; }
   else if(str.length() > markers + 1 && str[markers] == '0')
      { markers += 1; base = Octal; }

   *this = decode(reinterpret_cast<const byte*>(str.data()) + markers,
                  str.length() - markers, base);

   if(negative) set_sign(Negative);
   else         set_sign(Positive);
   }

/*
* Construct a BigInt from an encoded BigInt
*/
BigInt::BigInt(const byte input[], u32bit length, Base base)
   {
   set_sign(Positive);
   *this = decode(input, length, base);
   }

/*
* Construct a BigInt from an encoded BigInt
*/
BigInt::BigInt(RandomNumberGenerator& rng, u32bit bits)
   {
   set_sign(Positive);
   randomize(rng, bits);
   }

/*
* Swap this BigInt with another
*/
void BigInt::swap(BigInt& other)
   {
   reg.swap(other.reg);
   std::swap(signedness, other.signedness);
   }

/*
* Grow the internal storage
*/
void BigInt::grow_reg(u32bit n)
   {
   reg.grow_to(round_up(size() + n, 8));
   }

/*
* Grow the internal storage
*/
void BigInt::grow_to(u32bit n)
   {
   if(n > size())
      reg.grow_to(round_up(n, 8));
   }

/*
* Comparison Function
*/
s32bit BigInt::cmp(const BigInt& n, bool check_signs) const
   {
   if(check_signs)
      {
      if(n.is_positive() && this->is_negative()) return -1;
      if(n.is_negative() && this->is_positive()) return 1;
      if(n.is_negative() && this->is_negative())
         return (-bigint_cmp(data(), sig_words(), n.data(), n.sig_words()));
      }
   return bigint_cmp(data(), sig_words(), n.data(), n.sig_words());
   }

/*
* Convert this number to a u32bit, if possible
*/
u32bit BigInt::to_u32bit() const
   {
   if(is_negative())
      throw Encoding_Error("BigInt::to_u32bit: Number is negative");
   if(bits() >= 32)
      throw Encoding_Error("BigInt::to_u32bit: Number is too big to convert");

   u32bit out = 0;
   for(u32bit j = 0; j != 4; ++j)
      out = (out << 8) | byte_at(3-j);
   return out;
   }

/*
* Return byte n of this number
*/
byte BigInt::byte_at(u32bit n) const
   {
   const u32bit WORD_BYTES = sizeof(word);
   u32bit word_num = n / WORD_BYTES, byte_num = n % WORD_BYTES;
   if(word_num >= size())
      return 0;
   else
      return get_byte(WORD_BYTES - byte_num - 1, reg[word_num]);
   }

/*
* Return bit n of this number
*/
bool BigInt::get_bit(u32bit n) const
   {
   return ((word_at(n / MP_WORD_BITS) >> (n % MP_WORD_BITS)) & 1);
   }

/*
* Return bits {offset...offset+length}
*/
u32bit BigInt::get_substring(u32bit offset, u32bit length) const
   {
   if(length > 32)
      throw Invalid_Argument("BigInt::get_substring: Substring size too big");

   u64bit piece = 0;
   for(u32bit j = 0; j != 8; ++j)
      piece = (piece << 8) | byte_at((offset / 8) + (7-j));

   u64bit mask = (1 << length) - 1;
   u32bit shift = (offset % 8);

   return static_cast<u32bit>((piece >> shift) & mask);
   }

/*
* Set bit number n
*/
void BigInt::set_bit(u32bit n)
   {
   const u32bit which = n / MP_WORD_BITS;
   const word mask = static_cast<word>(1) << (n % MP_WORD_BITS);
   if(which >= size()) grow_to(which + 1);
   reg[which] |= mask;
   }

/*
* Clear bit number n
*/
void BigInt::clear_bit(u32bit n)
   {
   const u32bit which = n / MP_WORD_BITS;
   const word mask = static_cast<word>(1) << (n % MP_WORD_BITS);
   if(which < size())
      reg[which] &= ~mask;
   }

/*
* Clear all but the lowest n bits
*/
void BigInt::mask_bits(u32bit n)
   {
   if(n == 0) { clear(); return; }
   if(n >= bits()) return;

   const u32bit top_word = n / MP_WORD_BITS;
   const word mask = (static_cast<word>(1) << (n % MP_WORD_BITS)) - 1;

   if(top_word < size())
      for(u32bit j = top_word + 1; j != size(); ++j)
         reg[j] = 0;

   reg[top_word] &= mask;
   }

/*
* Count how many bytes are being used
*/
u32bit BigInt::bytes() const
   {
   return (bits() + 7) / 8;
   }

/*
* Count how many bits are being used
*/
u32bit BigInt::bits() const
   {
   if(sig_words() == 0)
      return 0;

   u32bit full_words = sig_words() - 1, top_bits = MP_WORD_BITS;
   word top_word = word_at(full_words), mask = MP_WORD_TOP_BIT;

   while(top_bits && ((top_word & mask) == 0))
      { mask >>= 1; top_bits--; }

   return (full_words * MP_WORD_BITS + top_bits);
   }

/*
* Calcluate the size in a certain base
*/
u32bit BigInt::encoded_size(Base base) const
   {
   static const double LOG_2_BASE_10 = 0.30102999566;

   if(base == Binary)
      return bytes();
   else if(base == Hexadecimal)
      return 2*bytes();
   else if(base == Octal)
      return ((bits() + 2) / 3);
   else if(base == Decimal)
      return static_cast<u32bit>((bits() * LOG_2_BASE_10) + 1);
   else
      throw Invalid_Argument("Unknown base for BigInt encoding");
   }

/*
* Set the sign
*/
void BigInt::set_sign(Sign s)
   {
   if(is_zero())
      signedness = Positive;
   else
      signedness = s;
   }

/*
* Reverse the value of the sign flag
*/
void BigInt::flip_sign()
   {
   set_sign(reverse_sign());
   }

/*
* Return the opposite value of the current sign
*/
BigInt::Sign BigInt::reverse_sign() const
   {
   if(sign() == Positive)
      return Negative;
   return Positive;
   }

/*
* Return the negation of this number
*/
BigInt BigInt::operator-() const
   {
   BigInt x = (*this);
   x.flip_sign();
   return x;
   }

/*
* Return the absolute value of this number
*/
BigInt BigInt::abs() const
   {
   BigInt x = (*this);
   x.set_sign(Positive);
   return x;
   }

/*
* Encode this number into bytes
*/
void BigInt::binary_encode(byte output[]) const
   {
   const u32bit sig_bytes = bytes();
   for(u32bit j = 0; j != sig_bytes; ++j)
      output[sig_bytes-j-1] = byte_at(j);
   }

/*
* Set this number to the value in buf
*/
void BigInt::binary_decode(const byte buf[], u32bit length)
   {
   const u32bit WORD_BYTES = sizeof(word);

   reg.create(round_up((length / WORD_BYTES) + 1, 8));

   for(u32bit j = 0; j != length / WORD_BYTES; ++j)
      {
      u32bit top = length - WORD_BYTES*j;
      for(u32bit k = WORD_BYTES; k > 0; --k)
         reg[j] = (reg[j] << 8) | buf[top - k];
      }
   for(u32bit j = 0; j != length % WORD_BYTES; ++j)
      reg[length / WORD_BYTES] = (reg[length / WORD_BYTES] << 8) | buf[j];
   }

/*
* Set this number to the value in buf
*/
void BigInt::binary_decode(const MemoryRegion<byte>& buf)
   {
   binary_decode(buf, buf.size());
   }

}
