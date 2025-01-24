/*
 * An abstraction for an arbitrarily large bitvector that can
 * optionally use the secure_allocator. All bitwise accesses and all
 * constructors are implemented in constant time. Otherwise, only methods
 * with the "ct_" pre-fix run in constant time.
 *
 * (C) 2023-2024 Jack Lloyd
 * (C) 2023-2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_BIT_VECTOR_H_
#define BOTAN_BIT_VECTOR_H_

#include <botan/concepts.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/secmem.h>
#include <botan/strong_type.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace Botan {

template <template <typename> typename AllocatorT>
class bitvector_base;

template <typename T>
struct is_bitvector : std::false_type {};

template <template <typename> typename T>
struct is_bitvector<bitvector_base<T>> : std::true_type {};

template <typename T>
constexpr static bool is_bitvector_v = is_bitvector<T>::value;

template <typename T>
concept bitvectorish = is_bitvector_v<strong_type_wrapped_type<T>>;

namespace detail {

template <typename T0, typename... Ts>
struct first_type {
      using type = T0;
};

// get the first type from a parameter pack
// TODO: C++26 will bring Parameter Pack indexing:
//       using first_t = Ts...[0];
template <typename... Ts>
   requires(sizeof...(Ts) > 0)
using first_t = typename first_type<Ts...>::type;

// get the first object from a parameter pack
// TODO: C++26 will bring Parameter Pack indexing:
//       auto first = s...[0];
template <typename T0, typename... Ts>
constexpr static first_t<T0, Ts...> first(T0&& t, Ts&&...) {
   return std::forward<T0>(t);
}

template <typename OutT, typename>
using as = OutT;

template <typename FnT, std::unsigned_integral BlockT, typename... ParamTs>
using blockwise_processing_callback_return_type = std::invoke_result_t<FnT, as<BlockT, ParamTs>...>;

template <typename FnT, typename BlockT, typename... ParamTs>
concept is_blockwise_processing_callback_return_type =
   std::unsigned_integral<BlockT> &&
   (std::same_as<BlockT, blockwise_processing_callback_return_type<FnT, BlockT, ParamTs...>> ||
    std::same_as<bool, blockwise_processing_callback_return_type<FnT, BlockT, ParamTs...>> ||
    std::same_as<void, blockwise_processing_callback_return_type<FnT, BlockT, ParamTs...>>);

template <typename FnT, typename... ParamTs>
concept blockwise_processing_callback_without_mask =
   is_blockwise_processing_callback_return_type<FnT, uint8_t, ParamTs...> &&
   is_blockwise_processing_callback_return_type<FnT, uint16_t, ParamTs...> &&
   is_blockwise_processing_callback_return_type<FnT, uint32_t, ParamTs...> &&
   is_blockwise_processing_callback_return_type<FnT, uint64_t, ParamTs...>;

template <typename FnT, typename... ParamTs>
concept blockwise_processing_callback_with_mask =
   is_blockwise_processing_callback_return_type<FnT, uint8_t, ParamTs..., uint8_t /* mask */> &&
   is_blockwise_processing_callback_return_type<FnT, uint16_t, ParamTs..., uint16_t /* mask */> &&
   is_blockwise_processing_callback_return_type<FnT, uint32_t, ParamTs..., uint32_t /* mask */> &&
   is_blockwise_processing_callback_return_type<FnT, uint64_t, ParamTs..., uint64_t /* mask */>;

/**
 * Defines the callback constraints for the BitRangeOperator. For further
 * details, see bitvector_base::range_operation().
 */
template <typename FnT, typename... ParamTs>
concept blockwise_processing_callback = blockwise_processing_callback_with_mask<FnT, ParamTs...> ||
                                        blockwise_processing_callback_without_mask<FnT, ParamTs...>;

template <typename FnT, typename... ParamTs>
concept manipulating_blockwise_processing_callback =
   (blockwise_processing_callback_without_mask<FnT, ParamTs...> &&
    std::same_as<uint32_t, blockwise_processing_callback_return_type<FnT, uint32_t, ParamTs...>>) ||
   (blockwise_processing_callback_with_mask<FnT, ParamTs...> &&
    std::same_as<uint32_t, blockwise_processing_callback_return_type<FnT, uint32_t, ParamTs..., first_t<ParamTs...>>>);

template <typename FnT, typename... ParamTs>
concept predicate_blockwise_processing_callback =
   (blockwise_processing_callback_without_mask<FnT, ParamTs...> &&
    std::same_as<bool, blockwise_processing_callback_return_type<FnT, uint32_t, ParamTs...>>) ||
   (blockwise_processing_callback_with_mask<FnT, ParamTs...> &&
    std::same_as<bool, blockwise_processing_callback_return_type<FnT, uint32_t, ParamTs..., first_t<ParamTs...>>>);

template <typename T>
class bitvector_iterator {
   private:
      using size_type = typename T::size_type;

   public:
      using difference_type = std::make_signed_t<size_type>;
      using value_type = std::remove_const_t<decltype(std::declval<T>().at(0))>;
      using pointer = value_type*;
      using reference = value_type&;

      // TODO: technically, this could be a random access iterator
      using iterator_category = std::bidirectional_iterator_tag;

   public:
      bitvector_iterator() = default;
      ~bitvector_iterator() = default;

      bitvector_iterator(T* bitvector, size_t offset) : m_bitvector(bitvector) { update(offset); }

      bitvector_iterator(const bitvector_iterator& other) noexcept : m_bitvector(other.m_bitvector) {
         update(other.m_offset);
      }

      bitvector_iterator(bitvector_iterator&& other) noexcept : m_bitvector(other.m_bitvector) {
         update(other.m_offset);
      }

      bitvector_iterator& operator=(const bitvector_iterator& other) noexcept {
         if(this != &other) {
            m_bitvector = other.m_bitvector;
            update(other.m_offset);
         }
         return *this;
      }

      bitvector_iterator& operator=(bitvector_iterator&& other) noexcept {
         m_bitvector = other.m_bitvector;
         update(other.m_offset);
         return *this;
      }

      bitvector_iterator& operator++() noexcept {
         update(signed_offset() + 1);
         return *this;
      }

      bitvector_iterator operator++(int) noexcept {
         auto copy = *this;
         update(signed_offset() + 1);
         return copy;
      }

      bitvector_iterator& operator--() noexcept {
         update(signed_offset() - 1);
         return *this;
      }

      bitvector_iterator operator--(int) noexcept {
         auto copy = *this;
         update(signed_offset() - 1);
         return copy;
      }

      std::partial_ordering operator<=>(const bitvector_iterator& other) const noexcept {
         if(m_bitvector == other.m_bitvector) {
            return m_offset <=> other.m_offset;
         } else {
            return std::partial_ordering::unordered;
         }
      }

      bool operator==(const bitvector_iterator& other) const noexcept {
         return m_bitvector == other.m_bitvector && m_offset == other.m_offset;
      }

      reference operator*() const { return m_bitref.value(); }

      pointer operator->() const { return &(m_bitref.value()); }

   private:
      void update(size_type new_offset) {
         m_offset = new_offset;
         if(m_offset < m_bitvector->size()) {
            m_bitref.emplace((*m_bitvector)[m_offset]);
         } else {
            // end() iterator
            m_bitref.reset();
         }
      }

      difference_type signed_offset() const { return static_cast<difference_type>(m_offset); }

   private:
      T* m_bitvector;
      size_type m_offset;
      mutable std::optional<value_type> m_bitref;
};

}  // namespace detail

/**
 * An arbitrarily large bitvector with typical bit manipulation and convenient
 * bitwise access methods. Don't use `bitvector_base` directly, but the type
 * aliases::
 *
 *    * bitvector         - with a standard allocator
 *    * secure_bitvector  - with a secure allocator that auto-scrubs the memory
 */
template <template <typename> typename AllocatorT>
class bitvector_base final {
   public:
      using block_type = uint8_t;
      using size_type = size_t;
      using allocator_type = AllocatorT<block_type>;
      using value_type = block_type;
      using iterator = detail::bitvector_iterator<bitvector_base<AllocatorT>>;
      using const_iterator = detail::bitvector_iterator<const bitvector_base<AllocatorT>>;

      static constexpr size_type block_size_bytes = sizeof(block_type);
      static constexpr size_type block_size_bits = block_size_bytes * 8;
      static constexpr bool uses_secure_allocator = std::is_same_v<allocator_type, secure_allocator<block_type>>;

   private:
      template <template <typename> typename FriendAllocatorT>
      friend class bitvector_base;

      static constexpr block_type one = block_type(1);

      static constexpr size_type block_offset_shift = size_type(3) + ceil_log2(block_size_bytes);
      static constexpr size_type block_index_mask = (one << block_offset_shift) - 1;

      static constexpr size_type block_index(size_type pos) { return pos >> block_offset_shift; }

      static constexpr size_type block_offset(size_type pos) { return pos & block_index_mask; }

   private:
      /**
       * Internal helper to wrap a single bit in the bitvector and provide
       * certain convenience access methods.
       */
      template <typename BlockT>
         requires std::same_as<block_type, std::remove_cv_t<BlockT>>
      class bitref_base {
         private:
            friend class bitvector_base<AllocatorT>;

            constexpr bitref_base(std::span<BlockT> blocks, size_type pos) noexcept :
                  m_block(blocks[block_index(pos)]), m_mask(one << block_offset(pos)) {}

         public:
            bitref_base() = delete;
            bitref_base(const bitref_base&) noexcept = default;
            bitref_base(bitref_base&&) noexcept = default;
            bitref_base& operator=(const bitref_base&) = delete;
            bitref_base& operator=(bitref_base&&) = delete;

            ~bitref_base() = default;

         public:
            constexpr operator bool() const noexcept { return is_set(); }

            constexpr bool is_set() const noexcept { return (m_block & m_mask) > 0; }

            template <std::integral T>
            constexpr T as() const noexcept {
               return static_cast<T>(is_set());
            }

            constexpr CT::Choice as_choice() const noexcept {
               return CT::Choice::from_int(static_cast<BlockT>(m_block & m_mask));
            }

         protected:
            BlockT& m_block;  // NOLINT(*-non-private-member-variables-in-classes)
            BlockT m_mask;    // NOLINT(*-non-private-member-variables-in-classes)
      };

   public:
      /**
       * Wraps a constant reference into the bitvector. Bit can be accessed
       * but not modified.
       */
      template <typename BlockT>
      class bitref final : public bitref_base<BlockT> {
         public:
            using bitref_base<BlockT>::bitref_base;
      };

      /**
       * Wraps a modifiable reference into the bitvector. Bit may be accessed
       * and modified (e.g. flipped or XOR'ed).
       *
       * Constant-time operations are used for the bit manipulations. The
       * location of the bit in the bit vector may be leaked, though.
       */
      template <typename BlockT>
         requires(!std::is_const_v<BlockT>)
      class bitref<BlockT> : public bitref_base<BlockT> {
         public:
            using bitref_base<BlockT>::bitref_base;

            ~bitref() = default;
            bitref(const bitref&) noexcept = default;
            bitref(bitref&&) noexcept = default;

            constexpr bitref& set() noexcept {
               this->m_block |= this->m_mask;
               return *this;
            }

            constexpr bitref& unset() noexcept {
               this->m_block &= ~this->m_mask;
               return *this;
            }

            constexpr bitref& flip() noexcept {
               this->m_block ^= this->m_mask;
               return *this;
            }

            // NOLINTBEGIN

            constexpr bitref& operator=(bool bit) noexcept {
               this->m_block =
                  CT::Mask<BlockT>::expand(bit).select(this->m_mask | this->m_block, this->m_block & ~this->m_mask);
               return *this;
            }

            constexpr bitref& operator=(const bitref& bit) noexcept { return *this = bit.is_set(); }

            constexpr bitref& operator=(bitref&& bit) noexcept { return *this = bit.is_set(); }

            // NOLINTEND

            constexpr bitref& operator&=(bool other) noexcept {
               this->m_block &= ~CT::Mask<BlockT>::expand(other).if_not_set_return(this->m_mask);
               return *this;
            }

            constexpr bitref& operator|=(bool other) noexcept {
               this->m_block |= CT::Mask<BlockT>::expand(other).if_set_return(this->m_mask);
               return *this;
            }

            constexpr bitref& operator^=(bool other) noexcept {
               this->m_block ^= CT::Mask<BlockT>::expand(other).if_set_return(this->m_mask);
               return *this;
            }
      };

   public:
      bitvector_base() : m_bits(0) {}

      bitvector_base(size_type bits) : m_bits(bits), m_blocks(ceil_toblocks(bits)) {}

      /**
       * Initialize the bitvector from a byte-array. Bits are taken byte-wise
       * from least significant to most significant. Example::
       *
       *    bitvector[0] -> LSB(Byte[0])
       *    bitvector[1] -> LSB+1(Byte[0])
       *    ...
       *    bitvector[8] -> LSB(Byte[1])
       *
       * @param bytes The byte vector to be loaded
       * @param bits  The number of bits to be loaded. This must not be more
       *              than the number of bytes in @p bytes.
       */
      bitvector_base(std::span<const uint8_t> bytes, std::optional<size_type> bits = std::nullopt) {
         from_bytes(bytes, bits);
      }

      bitvector_base(std::initializer_list<block_type> blocks, std::optional<size_type> bits = std::nullopt) :
            m_bits(bits.value_or(blocks.size() * block_size_bits)), m_blocks(blocks.begin(), blocks.end()) {}

      bool empty() const { return m_bits == 0; }

      size_type size() const { return m_bits; }

      /**
       * @returns true iff the number of 1-bits in this is odd, false otherwise (constant time)
       */
      CT::Choice has_odd_hamming_weight() const {
         uint64_t acc = 0;
         full_range_operation([&](std::unsigned_integral auto block) { acc ^= block; }, *this);

         for(size_t i = (sizeof(acc) * 8) >> 1; i > 0; i >>= 1) {
            acc ^= acc >> i;
         }

         return CT::Choice::from_int(acc & one);
      }

      /**
       * Counts the number of 1-bits in the bitvector in constant time.
       * @returns the "population count" (or hamming weight) of the bitvector
       */
      size_type hamming_weight() const {
         size_type acc = 0;
         full_range_operation([&](std::unsigned_integral auto block) { acc += ct_popcount(block); }, *this);
         return acc;
      }

      /**
       * @returns copies this bitvector into a new bitvector of type @p OutT
       */
      template <bitvectorish OutT>
      OutT as() const {
         return subvector<OutT>(0, size());
      }

      /**
       * @returns true if @p other contains the same bit pattern as this
       */
      template <bitvectorish OtherT>
      bool equals_vartime(const OtherT& other) const noexcept {
         return size() == other.size() &&
                full_range_operation([]<std::unsigned_integral BlockT>(BlockT lhs, BlockT rhs) { return lhs == rhs; },
                                     *this,
                                     unwrap_strong_type(other));
      }

      /**
       * @returns true if @p other contains the same bit pattern as this
       */
      template <bitvectorish OtherT>
      bool equals(const OtherT& other) const noexcept {
         return (*this ^ other).none();
      }

      /// @name Serialization
      /// @{

      /**
       * Re-initialize the bitvector with the given bytes. See the respective
       * constructor for details. This should be used only when trying to save
       * allocations. Otherwise, use the constructor.
       *
       * @param bytes  the byte range to load bits from
       * @param bits   (optional) if not all @p bytes should be loaded in full
       */
      void from_bytes(std::span<const uint8_t> bytes, std::optional<size_type> bits = std::nullopt) {
         m_bits = bits.value_or(bytes.size_bytes() * 8);
         BOTAN_ARG_CHECK(m_bits <= bytes.size_bytes() * 8, "not enough data to load so many bits");
         resize(m_bits);

         // load as much aligned data as possible
         const auto verbatim_blocks = m_bits / block_size_bits;
         const auto verbatim_bytes = verbatim_blocks * block_size_bytes;
         if(verbatim_blocks > 0) {
            typecast_copy(std::span{m_blocks}.first(verbatim_blocks), bytes.first(verbatim_bytes));
         }

         // load remaining unaligned data
         for(size_type i = verbatim_bytes * 8; i < m_bits; ++i) {
            ref(i) = ((bytes[i >> 3] & (uint8_t(1) << (i & 7))) != 0);
         }
      }

      /**
       * Renders the bitvector into a byte array. By default, this will use
       * `std::vector<uint8_t>` or `Botan::secure_vector<uint8_t>`, depending on
       * the allocator used by the bitvector. The rendering is compatible with
       * the bit layout explained in the respective constructor.
       */
      template <concepts::resizable_byte_buffer OutT =
                   std::conditional_t<uses_secure_allocator, secure_vector<uint8_t>, std::vector<uint8_t>>>
      OutT to_bytes() const {
         OutT out(ceil_tobytes(m_bits));
         to_bytes(out);
         return out;
      }

      /**
       * Renders the bitvector into a properly sized byte range.
       *
       * @param out  a byte range that has a length of at least `ceil_tobytes(size())`.
       */
      void to_bytes(std::span<uint8_t> out) const {
         const auto bytes_needed = ceil_tobytes(m_bits);
         BOTAN_ARG_CHECK(bytes_needed <= out.size_bytes(), "Not enough space to render bitvector");

         // copy as much aligned data as possible
         const auto verbatim_blocks = m_bits / block_size_bits;
         const auto verbatim_bytes = verbatim_blocks * block_size_bytes;
         if(verbatim_blocks > 0) {
            typecast_copy(out.first(verbatim_bytes), std::span{m_blocks}.first(verbatim_blocks));
         }

         // copy remaining unaligned data
         clear_mem(out.subspan(verbatim_bytes));
         for(size_type i = verbatim_bytes * 8; i < m_bits; ++i) {
            out[i >> 3] |= ref(i).template as<uint8_t>() << (i & 7);
         }
      }

      /**
       * Renders this bitvector into a sequence of "0"s and "1"s.
       * This is meant for debugging purposes and is not efficient.
       */
      std::string to_string() const {
         std::stringstream ss;
         for(size_type i = 0; i < size(); ++i) {
            ss << ref(i);
         }
         return ss.str();
      }

      /// @}

      /// @name Capacity Accessors and Modifiers
      /// @{

      size_type capacity() const { return m_blocks.capacity() * block_size_bits; }

      void reserve(size_type bits) { m_blocks.reserve(ceil_toblocks(bits)); }

      void resize(size_type bits) {
         const auto new_number_of_blocks = ceil_toblocks(bits);
         if(new_number_of_blocks != m_blocks.size()) {
            m_blocks.resize(new_number_of_blocks);
         }

         m_bits = bits;
         zero_unused_bits();
      }

      void push_back(bool bit) {
         const auto i = size();
         resize(i + 1);
         ref(i) = bit;
      }

      void pop_back() {
         if(!empty()) {
            resize(size() - 1);
         }
      }

      /// @}

      /// @name Bitwise and Global Accessors and Modifiers
      /// @{

      auto at(size_type pos) {
         check_offset(pos);
         return ref(pos);
      }

      // TODO C++23: deducing this
      auto at(size_type pos) const {
         check_offset(pos);
         return ref(pos);
      }

      auto front() { return ref(0); }

      // TODO C++23: deducing this
      auto front() const { return ref(0); }

      auto back() { return ref(size() - 1); }

      // TODO C++23: deducing this
      auto back() const { return ref(size() - 1); }

      /**
       * Sets the bit at position @p pos.
       * @throws Botan::Invalid_Argument if @p pos is out of range
       */
      bitvector_base& set(size_type pos) {
         check_offset(pos);
         ref(pos).set();
         return *this;
      }

      /**
       * Sets all currently allocated bits.
       */
      bitvector_base& set() {
         full_range_operation(
            [](std::unsigned_integral auto block) -> decltype(block) { return static_cast<decltype(block)>(~0); },
            *this);
         zero_unused_bits();
         return *this;
      }

      /**
       * Unsets the bit at position @p pos.
       * @throws Botan::Invalid_Argument if @p pos is out of range
       */
      bitvector_base& unset(size_type pos) {
         check_offset(pos);
         ref(pos).unset();
         return *this;
      }

      /**
       * Unsets all currently allocated bits.
       */
      bitvector_base& unset() {
         full_range_operation(
            [](std::unsigned_integral auto block) -> decltype(block) { return static_cast<decltype(block)>(0); },
            *this);
         return *this;
      }

      /**
       * Flips the bit at position @p pos.
       * @throws Botan::Invalid_Argument if @p pos is out of range
       */
      bitvector_base& flip(size_type pos) {
         check_offset(pos);
         ref(pos).flip();
         return *this;
      }

      /**
       * Flips all currently allocated bits.
       */
      bitvector_base& flip() {
         full_range_operation([](std::unsigned_integral auto block) -> decltype(block) { return ~block; }, *this);
         zero_unused_bits();
         return *this;
      }

      /**
       * @returns true iff no bit is set
       */
      bool none_vartime() const {
         return full_range_operation([](std::unsigned_integral auto block) { return block == 0; }, *this);
      }

      /**
       * @returns true iff no bit is set in constant time
       */
      bool none() const { return hamming_weight() == 0; }

      /**
       * @returns true iff at least one bit is set
       */
      bool any_vartime() const { return !none_vartime(); }

      /**
       * @returns true iff at least one bit is set in constant time
       */
      bool any() const { return !none(); }

      /**
       * @returns true iff all bits are set
       */
      bool all_vartime() const {
         return full_range_operation(
            []<std::unsigned_integral BlockT>(BlockT block, BlockT mask) { return block == mask; }, *this);
      }

      /**
       * @returns true iff all bits are set in constant time
       */
      bool all() const { return hamming_weight() == m_bits; }

      auto operator[](size_type pos) { return ref(pos); }

      // TODO C++23: deducing this
      auto operator[](size_type pos) const { return ref(pos); }

      /// @}

      /// @name Subvectors
      /// @{

      /**
       * Creates a new bitvector with a subsection of this bitvector starting at
       * @p pos copying exactly @p length bits.
       */
      template <bitvectorish OutT = bitvector_base<AllocatorT>>
      auto subvector(size_type pos, std::optional<size_type> length = std::nullopt) const {
         size_type bitlen = length.value_or(size() - pos);
         BOTAN_ARG_CHECK(pos + bitlen <= size(), "Not enough bits to copy");

         OutT newvector(bitlen);

         // Handle bitvectors that are wrapped in strong types
         auto& newvector_unwrapped = unwrap_strong_type(newvector);

         if(bitlen > 0) {
            if(pos % 8 == 0) {
               copy_mem(
                  newvector_unwrapped.m_blocks,
                  std::span{m_blocks}.subspan(block_index(pos), block_index(pos + bitlen - 1) - block_index(pos) + 1));
            } else {
               BitRangeOperator<const bitvector_base<AllocatorT>, BitRangeAlignment::no_alignment> from_op(
                  *this, pos, bitlen);
               BitRangeOperator<strong_type_wrapped_type<OutT>> to_op(
                  unwrap_strong_type(newvector_unwrapped), 0, bitlen);
               range_operation([](auto /* to */, auto from) { return from; }, to_op, from_op);
            }

            newvector_unwrapped.zero_unused_bits();
         }

         return newvector;
      }

      /**
       * Extracts a subvector of bits as an unsigned integral type @p OutT
       * starting from bit @p pos and copying exactly sizeof(OutT)*8 bits.
       *
       * Hint: The bits are in big-endian order, i.e. the least significant bit
       *       is the 0th bit and the most significant bit it the n-th. Hence,
       *       addressing the bits with bitwise operations is done like so:
       *       bool bit = (out_int >> pos) & 1;
       */
      template <typename OutT>
         requires(std::unsigned_integral<strong_type_wrapped_type<OutT>> &&
                  !std::same_as<bool, strong_type_wrapped_type<OutT>>)
      OutT subvector(size_type pos) const {
         using result_t = strong_type_wrapped_type<OutT>;
         constexpr size_t bits = sizeof(result_t) * 8;
         BOTAN_ARG_CHECK(pos + bits <= size(), "Not enough bits to copy");
         result_t out = 0;

         if(pos % 8 == 0) {
            out = load_le<result_t>(std::span{m_blocks}.subspan(block_index(pos)).template first<sizeof(result_t)>());
         } else {
            BitRangeOperator<const bitvector_base<AllocatorT>, BitRangeAlignment::no_alignment> op(*this, pos, bits);
            range_operation(
               [&](std::unsigned_integral auto integer) {
                  if constexpr(std::same_as<result_t, decltype(integer)>) {
                     out = integer;
                  }
               },
               op);
         }

         return wrap_strong_type<OutT>(out);
      }

      /**
       * Replaces a subvector of bits with the bits of another bitvector @p value
       * starting at bit @p pos. The number of bits to replace is determined by
       * the size of @p value.
       *
       * @note This is currently supported for byte-aligned @p pos only.
       *
       * @throws Not_Implemented when called with @p pos not divisible by 8.
       *
       * @param pos    the position to start replacing bits
       * @param value  the bitvector to copy bits from
       */
      template <typename InT>
         requires(std::unsigned_integral<strong_type_wrapped_type<InT>> && !std::same_as<bool, InT>)
      void subvector_replace(size_type pos, InT value) {
         using in_t = strong_type_wrapped_type<InT>;
         constexpr size_t bits = sizeof(in_t) * 8;
         BOTAN_ARG_CHECK(pos + bits <= size(), "Not enough bits to replace");

         if(pos % 8 == 0) {
            store_le(std::span{m_blocks}.subspan(block_index(pos)).template first<sizeof(in_t)>(),
                     unwrap_strong_type(value));
         } else {
            BitRangeOperator<bitvector_base<AllocatorT>, BitRangeAlignment::no_alignment> op(*this, pos, bits);
            range_operation(
               [&]<std::unsigned_integral BlockT>(BlockT block) -> BlockT {
                  if constexpr(std::same_as<in_t, BlockT>) {
                     return unwrap_strong_type(value);
                  } else {
                     // This should never be reached. BOTAN_ASSERT_UNREACHABLE()
                     // caused warning "unreachable code" on MSVC, though. You
                     // don't say!
                     //
                     // Returning the given block back, is the most reasonable
                     // thing to do in this case, though.
                     return block;
                  }
               },
               op);
         }
      }

      /// @}

      /// @name Operators
      ///
      /// @{

      auto operator~() {
         auto newbv = *this;
         newbv.flip();
         return newbv;
      }

      template <bitvectorish OtherT>
      auto& operator|=(const OtherT& other) {
         full_range_operation([]<std::unsigned_integral BlockT>(BlockT lhs, BlockT rhs) -> BlockT { return lhs | rhs; },
                              *this,
                              unwrap_strong_type(other));
         return *this;
      }

      template <bitvectorish OtherT>
      auto& operator&=(const OtherT& other) {
         full_range_operation([]<std::unsigned_integral BlockT>(BlockT lhs, BlockT rhs) -> BlockT { return lhs & rhs; },
                              *this,
                              unwrap_strong_type(other));
         return *this;
      }

      template <bitvectorish OtherT>
      auto& operator^=(const OtherT& other) {
         full_range_operation([]<std::unsigned_integral BlockT>(BlockT lhs, BlockT rhs) -> BlockT { return lhs ^ rhs; },
                              *this,
                              unwrap_strong_type(other));
         return *this;
      }

      /// @}

      /// @name Constant Time Operations
      ///
      /// @{

      /**
       * Implements::
       *
       *    if(condition) {
       *       *this ^= other;
       *    }
       *
       * omitting runtime dependence on any of the parameters.
       */
      template <bitvectorish OtherT>
      void ct_conditional_xor(CT::Choice condition, const OtherT& other) {
         BOTAN_ASSERT_NOMSG(m_bits == other.m_bits);
         BOTAN_ASSERT_NOMSG(m_blocks.size() == other.m_blocks.size());

         auto maybe_xor = overloaded{
            [m = CT::Mask<uint64_t>::from_choice(condition)](uint64_t lhs, uint64_t rhs) -> uint64_t {
               return lhs ^ m.if_set_return(rhs);
            },
            [m = CT::Mask<uint32_t>::from_choice(condition)](uint32_t lhs, uint32_t rhs) -> uint32_t {
               return lhs ^ m.if_set_return(rhs);
            },
            [m = CT::Mask<uint16_t>::from_choice(condition)](uint16_t lhs, uint16_t rhs) -> uint16_t {
               return lhs ^ m.if_set_return(rhs);
            },
            [m = CT::Mask<uint8_t>::from_choice(condition)](uint8_t lhs, uint8_t rhs) -> uint8_t {
               return lhs ^ m.if_set_return(rhs);
            },
         };

         full_range_operation(maybe_xor, *this, unwrap_strong_type(other));
      }

      constexpr void _const_time_poison() const { CT::poison(m_blocks); }

      constexpr void _const_time_unpoison() const { CT::unpoison(m_blocks); }

      /// @}

      /// @name Iterators
      ///
      /// @{

      iterator begin() noexcept { return iterator(this, 0); }

      const_iterator begin() const noexcept { return const_iterator(this, 0); }

      const_iterator cbegin() const noexcept { return const_iterator(this, 0); }

      iterator end() noexcept { return iterator(this, size()); }

      const_iterator end() const noexcept { return const_iterator(this, size()); }

      const_iterator cend() noexcept { return const_iterator(this, size()); }

      /// @}

   private:
      void check_offset(size_type pos) const {
         // BOTAN_ASSERT_NOMSG(!CT::is_poisoned(&m_bits, sizeof(m_bits)));
         // BOTAN_ASSERT_NOMSG(!CT::is_poisoned(&pos, sizeof(pos)));
         BOTAN_ARG_CHECK(pos < m_bits, "Out of range");
      }

      void zero_unused_bits() {
         const auto first_unused_bit = size();

         // Zero out any unused bits in the last block
         if(first_unused_bit % block_size_bits != 0) {
            const block_type mask = (one << block_offset(first_unused_bit)) - one;
            m_blocks[block_index(first_unused_bit)] &= mask;
         }
      }

      static constexpr size_type ceil_toblocks(size_type bits) {
         return (bits + block_size_bits - 1) / block_size_bits;
      }

      auto ref(size_type pos) const { return bitref<const block_type>(m_blocks, pos); }

      auto ref(size_type pos) { return bitref<block_type>(m_blocks, pos); }

   private:
      enum class BitRangeAlignment { byte_aligned, no_alignment };

      /**
       * Helper construction to implement bit range operations on the bitvector.
       * It basically implements an iterator to read and write blocks of bits
       * from the underlying bitvector. Where "blocks of bits" are unsigned
       * integers of varying bit lengths.
       *
       * If the iteration starts at a byte boundary in the underlying bitvector,
       * this applies certain optimizations (i.e. loading blocks of bits straight
       * from the underlying byte buffer). The optimizations are enabled at
       * compile time (with the template parameter `alignment`).
       */
      template <typename BitvectorT, auto alignment = BitRangeAlignment::byte_aligned>
         requires is_bitvector_v<std::remove_cvref_t<BitvectorT>>
      class BitRangeOperator {
         private:
            constexpr static bool is_const() { return std::is_const_v<BitvectorT>; }

            struct UnalignedDataHelper {
                  const uint8_t padding_bits;
                  const uint8_t bits_to_byte_alignment;
            };

         public:
            BitRangeOperator(BitvectorT& source, size_type start_bitoffset, size_type bitlength) :
                  m_source(source),
                  m_start_bitoffset(start_bitoffset),
                  m_bitlength(bitlength),
                  m_unaligned_helper({.padding_bits = static_cast<uint8_t>(start_bitoffset % 8),
                                      .bits_to_byte_alignment = static_cast<uint8_t>(8 - (start_bitoffset % 8))}),
                  m_read_bitpos(start_bitoffset),
                  m_write_bitpos(start_bitoffset) {
               BOTAN_ASSERT(is_byte_aligned() == (m_start_bitoffset % 8 == 0), "byte alignment guarantee");
               BOTAN_ASSERT(m_source.size() >= m_start_bitoffset + m_bitlength, "enough bytes in underlying source");
            }

            BitRangeOperator(BitvectorT& source) : BitRangeOperator(source, 0, source.size()) {}

            static constexpr bool is_byte_aligned() { return alignment == BitRangeAlignment::byte_aligned; }

            /**
             * @returns the overall number of bits to be iterated with this operator
             */
            size_type size() const { return m_bitlength; }

            /**
             * @returns the number of bits not yet read from this operator
             */
            size_type bits_to_read() const { return m_bitlength - m_read_bitpos + m_start_bitoffset; }

            /**
             * @returns the number of bits still to be written into this operator
             */
            size_type bits_to_write() const { return m_bitlength - m_write_bitpos + m_start_bitoffset; }

            /**
             * Loads the next block of bits from the underlying bitvector. No
             * bounds checks are performed. The caller can define the size of
             * the resulting unsigned integer block.
             */
            template <std::unsigned_integral BlockT>
            BlockT load_next() const {
               constexpr size_type block_size = sizeof(BlockT);
               constexpr size_type block_bits = block_size * 8;
               const auto bits_remaining = bits_to_read();

               BlockT result_block = 0;
               if constexpr(is_byte_aligned()) {
                  result_block = load_le(m_source.as_byte_span().subspan(read_bytepos()).template first<block_size>());
               } else {
                  const size_type byte_pos = read_bytepos();
                  const size_type bits_to_collect = std::min(block_bits, bits_to_read());

                  const uint8_t first_byte = m_source.as_byte_span()[byte_pos];

                  // Initialize the left-most bits from the first byte.
                  result_block = BlockT(first_byte) >> m_unaligned_helper.padding_bits;

                  // If more bits are needed, we pull them from the remaining bytes.
                  if(m_unaligned_helper.bits_to_byte_alignment < bits_to_collect) {
                     const BlockT block =
                        load_le(m_source.as_byte_span().subspan(byte_pos + 1).template first<block_size>());
                     result_block |= block << m_unaligned_helper.bits_to_byte_alignment;
                  }
               }

               m_read_bitpos += std::min(block_bits, bits_remaining);
               return result_block;
            }

            /**
             * Stores the next block of bits into the underlying bitvector.
             * No bounds checks are performed. Storing bit blocks that are not
             * aligned at a byte-boundary in the underlying bitvector is
             * currently not implemented.
             */
            template <std::unsigned_integral BlockT>
               requires(!is_const())
            void store_next(BlockT block) {
               constexpr size_type block_size = sizeof(BlockT);
               constexpr size_type block_bits = block_size * 8;

               if constexpr(is_byte_aligned()) {
                  auto sink = m_source.as_byte_span().subspan(write_bytepos()).template first<block_size>();
                  store_le(sink, block);
               } else {
                  const size_type byte_pos = write_bytepos();
                  const size_type bits_to_store = std::min(block_bits, bits_to_write());

                  uint8_t& first_byte = m_source.as_byte_span()[byte_pos];

                  // Set the left-most bits in the first byte, leaving all others unchanged
                  first_byte = (first_byte & uint8_t(0xFF >> m_unaligned_helper.bits_to_byte_alignment)) |
                               uint8_t(block << m_unaligned_helper.padding_bits);

                  // If more bits are provided, we store them in the remaining bytes.
                  if(m_unaligned_helper.bits_to_byte_alignment < bits_to_store) {
                     const auto remaining_bytes =
                        m_source.as_byte_span().subspan(byte_pos + 1).template first<block_size>();
                     const BlockT padding_mask = ~(BlockT(-1) >> m_unaligned_helper.bits_to_byte_alignment);
                     const BlockT new_bytes =
                        (load_le(remaining_bytes) & padding_mask) | block >> m_unaligned_helper.bits_to_byte_alignment;
                     store_le(remaining_bytes, new_bytes);
                  }
               }

               m_write_bitpos += std::min(block_bits, bits_to_write());
            }

            template <std::unsigned_integral BlockT>
               requires(is_byte_aligned() && !is_const())
            std::span<BlockT> span(size_type blocks) const {
               BOTAN_DEBUG_ASSERT(blocks == 0 || is_memory_aligned_to<BlockT>());
               BOTAN_DEBUG_ASSERT(read_bytepos() % sizeof(BlockT) == 0);
               // Intermittently casting to void* to avoid a compiler warning
               void* ptr = reinterpret_cast<void*>(m_source.as_byte_span().data() + read_bytepos());
               return {reinterpret_cast<BlockT*>(ptr), blocks};
            }

            template <std::unsigned_integral BlockT>
               requires(is_byte_aligned() && is_const())
            std::span<const BlockT> span(size_type blocks) const {
               BOTAN_DEBUG_ASSERT(blocks == 0 || is_memory_aligned_to<BlockT>());
               BOTAN_DEBUG_ASSERT(read_bytepos() % sizeof(BlockT) == 0);
               // Intermittently casting to void* to avoid a compiler warning
               const void* ptr = reinterpret_cast<const void*>(m_source.as_byte_span().data() + read_bytepos());
               return {reinterpret_cast<const BlockT*>(ptr), blocks};
            }

            void advance(size_type bytes)
               requires(is_byte_aligned())
            {
               m_read_bitpos += bytes * 8;
               m_write_bitpos += bytes * 8;
            }

            template <std::unsigned_integral BlockT>
               requires(is_byte_aligned())
            size_t is_memory_aligned_to() const {
               const void* cptr = m_source.as_byte_span().data() + read_bytepos();
               const void* ptr_before = cptr;

               // std::align takes `ptr` as a reference (!), i.e. `void*&` and
               // uses it as an out-param. Though, `cptr` is const because this
               // method is const-qualified, hence the const_cast<>.
               void* ptr = const_cast<void*>(cptr);
               size_t size = sizeof(BlockT);
               return ptr_before != nullptr && std::align(alignof(BlockT), size, ptr, size) == ptr_before;
            }

         private:
            size_type read_bytepos() const { return m_read_bitpos / 8; }

            size_type write_bytepos() const { return m_write_bitpos / 8; }

         private:
            BitvectorT& m_source;
            size_type m_start_bitoffset;
            size_type m_bitlength;

            UnalignedDataHelper m_unaligned_helper;

            mutable size_type m_read_bitpos;
            mutable size_type m_write_bitpos;
      };

      /**
       * Helper struct for the low-level handling of blockwise operations
       *
       * This has two main code paths: Optimized for byte-aligned ranges that
       * can simply be taken from memory as-is. And a generic implementation
       * that must assemble blocks from unaligned bits before processing.
       */
      template <typename FnT, typename... ParamTs>
         requires detail::blockwise_processing_callback<FnT, ParamTs...>
      class blockwise_processing_callback_trait {
         public:
            constexpr static bool needs_mask = detail::blockwise_processing_callback_with_mask<FnT, ParamTs...>;
            constexpr static bool is_manipulator = detail::manipulating_blockwise_processing_callback<FnT, ParamTs...>;
            constexpr static bool is_predicate = detail::predicate_blockwise_processing_callback<FnT, ParamTs...>;
            static_assert(!is_manipulator || !is_predicate, "cannot be manipulator and predicate at the same time");

            /**
             * Applies @p fn to the blocks provided in @p blocks by simply reading from
             * memory without re-arranging any bits across byte-boundaries.
             */
            template <std::unsigned_integral... BlockTs>
               requires(all_same_v<std::remove_cv_t<BlockTs>...> && sizeof...(BlockTs) == sizeof...(ParamTs))
            constexpr static bool apply_on_full_blocks(FnT fn, std::span<BlockTs>... blocks) {
               constexpr size_type bits = sizeof(detail::first_t<BlockTs...>) * 8;
               const size_type iterations = detail::first(blocks...).size();
               for(size_type i = 0; i < iterations; ++i) {
                  if constexpr(is_predicate) {
                     if(!apply(fn, bits, blocks[i]...)) {
                        return false;
                     }
                  } else if constexpr(is_manipulator) {
                     detail::first(blocks...)[i] = apply(fn, bits, blocks[i]...);
                  } else {
                     apply(fn, bits, blocks[i]...);
                  }
               }
               return true;
            }

            /**
             * Applies @p fn to as many blocks as @p ops provide for the given type.
             */
            template <std::unsigned_integral BlockT, typename... BitRangeOperatorTs>
               requires(sizeof...(BitRangeOperatorTs) == sizeof...(ParamTs))
            constexpr static bool apply_on_unaligned_blocks(FnT fn, BitRangeOperatorTs&... ops) {
               constexpr size_type block_bits = sizeof(BlockT) * 8;
               auto bits = detail::first(ops...).bits_to_read();
               if(bits == 0) {
                  return true;
               }

               bits += block_bits;  // avoid unsigned integer underflow in the following loop
               while(bits > block_bits * 2 - 8) {
                  bits -= block_bits;
                  if constexpr(is_predicate) {
                     if(!apply(fn, bits, ops.template load_next<BlockT>()...)) {
                        return false;
                     }
                  } else if constexpr(is_manipulator) {
                     detail::first(ops...).store_next(apply(fn, bits, ops.template load_next<BlockT>()...));
                  } else {
                     apply(fn, bits, ops.template load_next<BlockT>()...);
                  }
               }
               return true;
            }

         private:
            template <std::unsigned_integral... BlockTs>
               requires(all_same_v<BlockTs...>)
            constexpr static auto apply(FnT fn, size_type bits, BlockTs... blocks) {
               if constexpr(needs_mask) {
                  return fn(blocks..., make_mask<detail::first_t<BlockTs...>>(bits));
               } else {
                  return fn(blocks...);
               }
            }
      };

      /**
       * Helper function of `full_range_operation` and `range_operation` that
       * calls @p fn on a given aligned unsigned integer block as long as the
       * underlying bit range contains enough bits to fill the block fully.
       *
       * This uses bare memory access to gain a speed up for aligned data.
       */
      template <std::unsigned_integral BlockT, typename FnT, typename... BitRangeOperatorTs>
         requires(detail::blockwise_processing_callback<FnT, BitRangeOperatorTs...> &&
                  sizeof...(BitRangeOperatorTs) > 0)
      static bool _process_in_fully_aligned_blocks_of(FnT fn, BitRangeOperatorTs&... ops) {
         constexpr size_type block_bytes = sizeof(BlockT);
         constexpr size_type block_bits = block_bytes * 8;
         const size_type blocks = detail::first(ops...).bits_to_read() / block_bits;

         using callback_trait = blockwise_processing_callback_trait<FnT, BitRangeOperatorTs...>;
         const auto result = callback_trait::apply_on_full_blocks(fn, ops.template span<BlockT>(blocks)...);
         (ops.advance(block_bytes * blocks), ...);
         return result;
      }

      /**
       * Helper function of `full_range_operation` and `range_operation` that
       * calls @p fn on a given unsigned integer block size as long as the
       * underlying bit range contains enough bits to fill the block.
       */
      template <std::unsigned_integral BlockT, typename FnT, typename... BitRangeOperatorTs>
         requires(detail::blockwise_processing_callback<FnT, BitRangeOperatorTs...>)
      static bool _process_in_unaligned_blocks_of(FnT fn, BitRangeOperatorTs&... ops) {
         using callback_trait = blockwise_processing_callback_trait<FnT, BitRangeOperatorTs...>;
         return callback_trait::template apply_on_unaligned_blocks<BlockT>(fn, ops...);
      }

      /**
       * Apply @p fn to all bits in the ranges defined by @p ops. If more than
       * one range operator is passed to @p ops, @p fn receives corresponding
       * blocks of bits from each operator. Therefore, all @p ops have to define
       * the exact same length of their underlying ranges.
       *
       * @p fn may return a bit block that will be stored into the _first_ bit
       * range passed into @p ops. If @p fn returns a boolean, and its value is
       * `false`, the range operation is cancelled and `false` is returned.
       *
       * The implementation ensures to pull bits in the largest bit blocks
       * possible and reverts to smaller bit blocks only when needed.
       */
      template <typename FnT, typename... BitRangeOperatorTs>
         requires(detail::blockwise_processing_callback<FnT, BitRangeOperatorTs...> &&
                  sizeof...(BitRangeOperatorTs) > 0)
      static bool range_operation(FnT fn, BitRangeOperatorTs... ops) {
         BOTAN_ASSERT(has_equal_lengths(ops...), "all BitRangeOperators have the same length");

         if constexpr((BitRangeOperatorTs::is_byte_aligned() && ...)) {
            // Note: At the moment we can assume that this will always be used
            //       on the _entire_ bitvector. Therefore, we can safely assume
            //       that the bitvectors' underlying buffers are properly aligned.
            //       If this assumption changes, we need to add further handling
            //       to process a byte padding at the beginning of the bitvector
            //       until a memory alignment boundary is reached.
            const bool alignment = (ops.template is_memory_aligned_to<uint64_t>() && ...);
            BOTAN_ASSERT_NOMSG(alignment);

            return _process_in_fully_aligned_blocks_of<uint64_t>(fn, ops...) &&
                   _process_in_fully_aligned_blocks_of<uint32_t>(fn, ops...) &&
                   _process_in_fully_aligned_blocks_of<uint16_t>(fn, ops...) &&
                   _process_in_unaligned_blocks_of<uint8_t>(fn, ops...);
         } else {
            return _process_in_unaligned_blocks_of<uint64_t>(fn, ops...) &&
                   _process_in_unaligned_blocks_of<uint32_t>(fn, ops...) &&
                   _process_in_unaligned_blocks_of<uint16_t>(fn, ops...) &&
                   _process_in_unaligned_blocks_of<uint8_t>(fn, ops...);
         }
      }

      /**
       * Apply @p fn to all bit blocks in the bitvector(s).
       */
      template <typename FnT, typename... BitvectorTs>
         requires(detail::blockwise_processing_callback<FnT, BitvectorTs...> &&
                  (is_bitvector_v<std::remove_cvref_t<BitvectorTs>> && ... && true))
      static bool full_range_operation(FnT&& fn, BitvectorTs&... bitvecs) {
         BOTAN_ASSERT(has_equal_lengths(bitvecs...), "all bitvectors have the same length");
         return range_operation(std::forward<FnT>(fn), BitRangeOperator<BitvectorTs>(bitvecs)...);
      }

      template <typename SomeT, typename... SomeTs>
      static bool has_equal_lengths(const SomeT& v, const SomeTs&... vs) {
         return ((v.size() == vs.size()) && ... && true);
      }

      template <std::unsigned_integral T>
      static constexpr T make_mask(size_type bits) {
         const bool max = bits >= sizeof(T) * 8;
         bits &= T(max - 1);
         return (T(!max) << bits) - 1;
      }

      auto as_byte_span() { return std::span{m_blocks.data(), m_blocks.size() * sizeof(block_type)}; }

      auto as_byte_span() const { return std::span{m_blocks.data(), m_blocks.size() * sizeof(block_type)}; }

   private:
      size_type m_bits;
      std::vector<block_type, allocator_type> m_blocks;
};

using secure_bitvector = bitvector_base<secure_allocator>;
using bitvector = bitvector_base<std::allocator>;

namespace detail {

/**
 * If one of the allocators is a Botan::secure_allocator, this will always
 * prefer it. Otherwise, the allocator of @p lhs will be used as a default.
 */
template <bitvectorish T1, bitvectorish T2>
constexpr auto copy_lhs_allocator_aware(const T1& lhs, const T2&) {
   constexpr bool needs_secure_allocator =
      strong_type_wrapped_type<T1>::uses_secure_allocator || strong_type_wrapped_type<T2>::uses_secure_allocator;

   if constexpr(needs_secure_allocator) {
      return lhs.template as<secure_bitvector>();
   } else {
      return lhs.template as<bitvector>();
   }
}

}  // namespace detail

template <bitvectorish T1, bitvectorish T2>
auto operator|(const T1& lhs, const T2& rhs) {
   auto res = detail::copy_lhs_allocator_aware(lhs, rhs);
   res |= rhs;
   return res;
}

template <bitvectorish T1, bitvectorish T2>
auto operator&(const T1& lhs, const T2& rhs) {
   auto res = detail::copy_lhs_allocator_aware(lhs, rhs);
   res &= rhs;
   return res;
}

template <bitvectorish T1, bitvectorish T2>
auto operator^(const T1& lhs, const T2& rhs) {
   auto res = detail::copy_lhs_allocator_aware(lhs, rhs);
   res ^= rhs;
   return res;
}

template <bitvectorish T1, bitvectorish T2>
bool operator==(const T1& lhs, const T2& rhs) {
   return lhs.equals_vartime(rhs);
}

template <bitvectorish T1, bitvectorish T2>
bool operator!=(const T1& lhs, const T2& rhs) {
   return lhs.equals_vartime(rhs);
}

namespace detail {

/**
 * A Strong<> adapter for arbitrarily large bitvectors
 */
template <concepts::container T>
   requires is_bitvector_v<T>
class Strong_Adapter<T> : public Container_Strong_Adapter_Base<T> {
   public:
      using size_type = typename T::size_type;

   public:
      using Container_Strong_Adapter_Base<T>::Container_Strong_Adapter_Base;

      auto at(size_type i) const { return this->get().at(i); }

      auto at(size_type i) { return this->get().at(i); }

      auto set(size_type i) { return this->get().set(i); }

      auto unset(size_type i) { return this->get().unset(i); }

      auto flip(size_type i) { return this->get().flip(i); }

      auto flip() { return this->get().flip(); }

      template <typename OutT>
      auto as() const {
         return this->get().template as<OutT>();
      }

      template <bitvectorish OutT = T>
      auto subvector(size_type pos, std::optional<size_type> length = std::nullopt) const {
         return this->get().template subvector<OutT>(pos, length);
      }

      template <typename OutT>
         requires(std::unsigned_integral<strong_type_wrapped_type<OutT>> &&
                  !std::same_as<bool, strong_type_wrapped_type<OutT>>)
      auto subvector(size_type pos) const {
         return this->get().template subvector<OutT>(pos);
      }

      template <typename InT>
         requires(std::unsigned_integral<strong_type_wrapped_type<InT>> && !std::same_as<bool, InT>)
      void subvector_replace(size_type pos, InT value) {
         return this->get().subvector_replace(pos, value);
      }

      template <bitvectorish OtherT>
      auto equals(const OtherT& other) const {
         return this->get().equals(other);
      }

      auto push_back(bool b) { return this->get().push_back(b); }

      auto pop_back() { return this->get().pop_back(); }

      auto front() const { return this->get().front(); }

      auto front() { return this->get().front(); }

      auto back() const { return this->get().back(); }

      auto back() { return this->get().back(); }

      auto any_vartime() const { return this->get().any_vartime(); }

      auto all_vartime() const { return this->get().all_vartime(); }

      auto none_vartime() const { return this->get().none_vartime(); }

      auto has_odd_hamming_weight() const { return this->get().has_odd_hamming_weight(); }

      auto hamming_weight() const { return this->get().hamming_weight(); }

      auto from_bytes(std::span<const uint8_t> bytes, std::optional<size_type> bits = std::nullopt) {
         return this->get().from_bytes(bytes, bits);
      }

      template <typename OutT = T>
      auto to_bytes() const {
         return this->get().template to_bytes<OutT>();
      }

      auto to_bytes(std::span<uint8_t> out) const { return this->get().to_bytes(out); }

      auto to_string() const { return this->get().to_string(); }

      auto capacity() const { return this->get().capacity(); }

      auto reserve(size_type n) { return this->get().reserve(n); }

      constexpr void _const_time_poison() const { this->get()._const_time_poison(); }

      constexpr void _const_time_unpoison() const { this->get()._const_time_unpoison(); }
};

}  // namespace detail

}  // namespace Botan

#endif
