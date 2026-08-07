.. _names:

Name Types
========================================

Botan provides a small set of strongly-typed value classes for names that appear in
network protocols and PKI artifacts: DNS host names, email addresses, IP addresses
(v4 and v6), and URIs.

Although these types were introduced to model the ``GeneralName`` alternatives of an
X.509 certificate (RFC 5280 4.2.1.6), they are not specifically tied to X.509 and are
intended to be reusable wherever names over these forms are useful.

Construction of these name types goes through a static parser (``from_string``) that
returns ``std::optional``; an empty optional signals a parse / validation failure.
Successfully constructed values are in a canonical form (for example, DNS names are
lowercased), so equality is defined on the canonical representation rather than on
the original input.

All of the types defined here are value types with equality comparison; all except
the subnet types additionally provide ordering via ``operator<=>``.

.. _dns_name:

DNS Names
----------------------------------------

.. versionadded:: 3.13

Declared in ``botan/dns_name.h``.

.. cpp:class:: DNSName

   A DNS name (host name or wildcard pattern) in canonical form. Construction
   validates that the input conforms to the Preferred Name Syntax (:rfc:`1035` and
   :rfc:`1123` LDH labels, length limits, no leading or trailing dot). Entirely
   numeric names (``"1.2.3.4"``) are rejected. The stored form is lowercased ASCII.

   .. cpp:function:: static std::optional<DNSName> from_string(std::string_view name)

      Parse and canonicalize a literal hostname. Returns ``std::nullopt`` if *name*
      is not a valid DNS name per RFCs 1035 / 1123, or if it contains a ``"*"``
      character - use :cpp:func:`from_san_string` for wildcards.

   .. cpp:function:: static std::optional<DNSName> from_san_string(std::string_view name)

      Like :cpp:func:`from_string`, but additionally accepts the :rfc:`6125` Section
      6.4.3 wildcard form: a single ``"*"`` anywhere within the leftmost label of an
      otherwise-valid DNS name (e.g. ``"*.example.com"``, ``"foo*.example.com"``).
      Shapes that could never produce a match under the wildcard rules - multiple ``"*"``
      (``"*.*.example.com"``), ``"*"`` outside the leftmost label
      (``"foo.*.example.com"``), or patterns with fewer than three labels (``"*"``,
      ``"*.com"``) - are rejected, as are wildcards embedded within an IDNA A-label
      (``"xn--f*.example.com"``). Intended for parsing X.509 SAN ``dnsName``
      entries.

      .. note::

         In a future major release, Botan's wildcard semantics will instead follow
         :rfc:`9525`, at which time this function will only accept wildcards of
         the form ``"*.example.com"``.

   .. cpp:function:: const std::string& name() const
   .. cpp:function:: const std::string& to_string() const

      Return the canonicalized (lowercase ASCII) form of the name. Both accessors
      return the same value; ``to_string`` matches the convention used by the other
      name types.

   .. cpp:function:: bool is_wildcard() const

      True if this name is a wildcard pattern. Since :cpp:func:`from_san_string`
      rejects any wildcard shape outside the leftmost label, any stored ``"*"`` is
      already in the leftmost label.

   .. cpp:function:: bool matches_wildcard(std::string_view wildcard) const

      Test whether this name matches the *wildcard* pattern. Equivalent to
      ``host_wildcard_match(wildcard, this->name())``.

   .. cpp:function:: static bool host_wildcard_match(std::string_view issued, \
                                                     std::string_view host)

      Test whether the issued name (possibly a wildcard pattern) matches *host*
      (which must be a complete and valid DNS name). Returns false if either input is
      invalid.

.. _email_address:

Email Addresses
----------------------------------------

.. versionadded:: 3.13

Declared in ``botan/email.h``.

Botan distinguishes two mailbox name types:

* :cpp:class:`EmailAddress` models RFC 5280 ``rfc822Name``, in which the local-part
  is ASCII only.

* :cpp:class:`SmtpUtf8Mailbox` models the :rfc:`9598` internationalized mailbox form, in
  which the local-part is UTF-8 and (per the RFC) MUST contain a non-ASCII character.
  Botan does not currently enforce the latter requirement when parsing; see below.

These types are intentionally not related to each other in the type system: name
constraint processing rules apply differently to the two forms, and by a strict
reading of the relevant RFCs their values should be entirely disjoint.

Both parsers accept only the unquoted dot-atom form of local-part; addresses that would
require quoting are currently rejected. The local-part is stored and compared verbatim
(case sensitively), while the domain is canonicalized as a :cpp:class:`DNSName`.

.. cpp:class:: EmailAddress

   A parsed email address in mailbox form ``local-part@domain``, modeling RFC 5280
   ``rfc822Name``. The local-part is restricted to ASCII.

   .. cpp:function:: static std::optional<EmailAddress> from_string(std::string_view addr)

      Parse *addr*. Returns ``std::nullopt`` if the input is not a valid mailbox, the
      local-part contains non-ASCII bytes, or the domain is not a valid DNS name.

   .. cpp:function:: const std::string& local_part() const

      The local-part, ASCII only.

   .. cpp:function:: const DNSName& domain() const

      The domain as a :cpp:class:`DNSName`.

   .. cpp:function:: std::string to_string() const

      The reassembled ``local-part@domain`` form. Note that the domain name will be in
      canonicalized form.

.. cpp:class:: SmtpUtf8Mailbox

   A parsed internationalized mailbox (``SmtpUTF8Mailbox``) as defined by :rfc:`9598`.
   The local-part is UTF-8, and the DNS name must be A-label form ASCII.
   Previous specifications of this type, from :rfc:`6531`, also accepted U-label
   domain names, but :rfc:`9598` modifies it to only contain an A-label.

   .. cpp:function:: static std::optional<SmtpUtf8Mailbox> from_string(std::string_view addr)

      Parse *addr*. Returns ``std::nullopt`` if the input is not a valid mailbox,
      is not valid UTF-8, or the domain is not a valid DNS name. The RFC 9598
      requirement that the local-part contain at least one non-ASCII character is
      not currently enforced here; an all-ASCII mailbox also parses.

   .. cpp:function:: const std::string& local_part() const
   .. cpp:function:: const DNSName& domain() const
   .. cpp:function:: std::string to_string() const

      As for :cpp:class:`EmailAddress`.

.. _ip_address:

IP Addresses and Subnets
----------------------------------------

.. versionadded:: 3.12

Declared in ``botan/ipv4_address.h`` and ``botan/ipv6_address.h``.

Botan provides separate IPv4 and IPv6 address types, each paired with a CIDR subnet type.
The subnet types are convenient for X.509 name constraints, which encode a network
address paired with a netmask.

IPv4
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. cpp:class:: IPv4Address

   A 32-bit IPv4 address.

   .. cpp:function:: explicit IPv4Address(uint32_t ip)

      Construct from a 32-bit big-endian integer representation.

   .. cpp:function:: static std::optional<IPv4Address> from_string(std::string_view str)

      Parse a dotted-decimal address (e.g. ``"10.0.0.1"``). Returns ``std::nullopt``
      on failure.

      Some libraries will accept strings like ``"127.1"``, ``"2130706433"``
      ``"0x7f000001"``, or `"0177.0.0x1"`` as valid encodings of the address
      ``"127.0.0.1"``. None of these alternate encodings are accepted by this function.

   .. cpp:function:: static IPv4Address netmask(size_t bits)

      Return an address with the leading *bits* set to one and the remainder zero.
      Throws ``Invalid_Argument`` if *bits* > 32.

   .. cpp:function:: static IPv4Address host_mask()

      Equivalent to ``netmask(32)``.

   .. cpp:function:: uint32_t address() const

      The address as a 32-bit big-endian integer.

   .. cpp:function:: std::array<uint8_t, 4> to_bytes() const

      The address as four bytes in network-byte-order.

   .. cpp:function:: std::string to_string() const

      Return the dotted-decimal form (e.g. ``"10.0.0.1"``).

   .. cpp:function:: std::optional<size_t> prefix_length() const

      If this value is a netmask consisting of a run of one bits followed by a run of
      zero bits, return the count of one bits; otherwise returns ``std::nullopt``.

   .. cpp:function:: IPv4Address operator&(const IPv4Address& other) const

      Bitwise AND, useful for masking an address with a netmask.

.. cpp:class:: IPv4Subnet

   An IPv4 subnet in CIDR form: a network address paired with a prefix length.

   .. cpp:function:: IPv4Subnet(IPv4Address address, size_t prefix_length)

      Construct from a network address and a *prefix_length* in ``[0, 32]``.
      Any set host bits of *address* are cleared. Throws ``Invalid_Argument`` if
      *prefix_length* > 32.

   .. cpp:function:: static std::optional<IPv4Subnet> from_string(std::string_view str)

      Parse the CIDR form ``"10.0.0.0/8"``. The ``/N`` suffix is required; bare
      addresses should be parsed via :cpp:func:`IPv4Address::from_string` and wrapped
      with :cpp:func:`IPv4Subnet::host` if needed.

      The input must already be canonical, such that ``from_string`` and ``to_string``
      are exact inverses: the prefix length is canonical decimal (``"/8"``, not ``"/08"``)
      and the host bits are clear (``"10.0.0.0/8"``, not ``"10.1.2.3/8"``).

      Unlike the constructor, which masks host bits away, a set host bit here is a parse
      failure. Returns ``std::nullopt`` on parse failure, non-canonical input, or
      out-of-range prefix length.

   .. cpp:function:: static std::optional<IPv4Subnet> from_address_and_mask( \
                     uint32_t addr, uint32_t mask)
   .. cpp:function:: static std::optional<IPv4Subnet> from_address_and_mask( \
                     std::span<const uint8_t, 8> addr_and_mask)

      Construct a subnet from a network address and a contiguous-CIDR netmask. Returns
      ``std::nullopt`` if the netmask has non-contiguous bits. Host bits are cleared.

   .. cpp:function:: static IPv4Subnet host(IPv4Address address)

      A single-host subnet (prefix length 32) covering exactly *address*.

   .. cpp:function:: const IPv4Address& address() const
   .. cpp:function:: size_t prefix_length() const
   .. cpp:function:: bool is_host() const
   .. cpp:function:: bool contains(const IPv4Address& ip) const
   .. cpp:function:: std::string to_string() const

      Accessors. ``to_string`` returns the CIDR form.

   .. cpp:function:: std::vector<uint8_t> serialize() const

      Bytes for use in a DER-encoded ``GeneralName`` ``iPAddress`` field. If
      :cpp:func:`is_host` is true, the output is 4 bytes (the address in network
      order); otherwise it is 8 bytes (``address || netmask``).

IPv6
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. cpp:class:: IPv6Address

   A 128-bit IPv6 address.

   .. cpp:function:: explicit IPv6Address(std::array<uint8_t, 16> ip)
   .. cpp:function:: explicit IPv6Address(std::span<const uint8_t, 16> ip)

      Construct from a 16-byte network-byte-order representation.

   .. cpp:function:: static std::optional<IPv6Address> from_string(std::string_view str)

      Parse a textual IPv6 address. Accepts the full form (eight colon-separated hex
      groups), the ``"::"``-compressed form (exactly one run of zero groups elided), and
      combinations such as ``"2001:db8::1"``. The IPv4 dotted-decimal format
      (e.g. ``"::ffff:192.0.2.1"``) is also accepted. Surrounding brackets and zone
      identifiers are not accepted.

   .. cpp:function:: static IPv6Address netmask(size_t bits)

      Return an address with the leading *bits* set to one and the remainder zero.
      Throws ``Invalid_Argument`` if *bits* > 128.

   .. cpp:function:: static IPv6Address host_mask()

      Equivalent to ``netmask(128)``.

   .. cpp:function:: std::array<uint8_t, 16> address() const

      Returns the 16 bytes of the address, in network-byte-order.

   .. cpp:function:: std::string to_string() const

      Returns the :rfc:`5952` canonical text form: lowercase hex, leading zeros within a
      group suppressed, and the longest run of two or more zero groups compressed with
      ``"::"``. The mixed hex/dotted notation is never produced, even for IPv4-mapped
      addresses.

   .. cpp:function:: std::optional<size_t> prefix_length() const

      As for :cpp:func:`IPv4Address::prefix_length`.

   .. cpp:function:: std::optional<IPv4Address> as_ipv4() const

      If this address is an IPv4-compatible IPv6 address (:rfc:`4291` 2.5.5.1) or an
      IPv4-mapped IPv6 address (:rfc:`4291` 2.5.5.2), return the embedded
      :cpp:class:`IPv4Address`. Otherwise return ``std::nullopt``.

   .. cpp:function:: IPv6Address operator&(const IPv6Address& other) const

      Bitwise AND.

.. cpp:class:: IPv6Subnet

   An IPv6 subnet in CIDR form. The interface mirrors :cpp:class:`IPv4Subnet`,
   with the prefix length valid in ``[0, 128]``.

   .. cpp:function:: IPv6Subnet(IPv6Address address, size_t prefix_length)
   .. cpp:function:: static std::optional<IPv6Subnet> from_string(std::string_view str)
   .. cpp:function:: static std::optional<IPv6Subnet> from_address_and_mask( \
                     std::span<const uint8_t, 32> addr_and_mask)
   .. cpp:function:: static IPv6Subnet host(IPv6Address address)
   .. cpp:function:: const IPv6Address& address() const
   .. cpp:function:: size_t prefix_length() const
   .. cpp:function:: bool is_host() const
   .. cpp:function:: bool contains(const IPv6Address& ip) const
   .. cpp:function:: std::string to_string() const

      As for the IPv4 counterparts. Note that ``from_string`` requires canonical
      input: the address must be in :rfc:`5952` form with host bits clear, and in
      particular the IPv4-mapped dotted form (``"::ffff:1.2.3.4/120"``) is rejected
      even though :cpp:func:`IPv6Address::from_string` accepts that address.

   .. cpp:function:: std::vector<uint8_t> serialize() const

      Bytes for use in a DER-encoded ``GeneralName`` ``iPAddress`` field:

      * 16 bytes (the address) if :cpp:func:`is_host`; the SAN form per
        RFC 5280 4.2.1.6.
      * 32 bytes (``address || netmask``) otherwise; the name-constraint
        form per RFC 5280 4.2.1.10.

.. _uri:

URIs
----------------------------------------

.. versionadded:: 3.13

Declared in ``botan/uri.h``.

.. cpp:class:: URI

   A URI parsed as a subset of :rfc:`3986`. The parser is intended to cover the shapes
   that appear in X.509 ``uniformResourceIdentifier`` GeneralName entries and similar
   PKI / network use; it is not a general-purpose URI library and does not perform
   pct-decoding or normalization beyond lowercasing the scheme. Percent escapes in the
   userinfo, path, query, and fragment components are validated for well-formedness (and
   ``"%00"`` is rejected outright) but are not decoded. Note that this non-canonicalization
   of the userinfo, path, query and fragment components implies that equality tests
   can be bypassed by varying pct encodings.

   The authority component is optional: URIs without one (e.g. ``"mailto:user@example.com"``)
   parse successfully. When an authority is present, its host portion is held as a
   validated :cpp:class:`DNSName`, :cpp:class:`IPv4Address`, or :cpp:class:`IPv6Address`
   (see :cpp:type:`Host`).

   .. cpp:type:: Host = Authority::Host

      A validated DNS name, or a literal IPv4 or IPv6 address.

   .. cpp:type:: HostKind = Authority::HostKind

      Tag for the alternative held by :cpp:type:`Host`.

   .. cpp:function:: static std::optional<URI> from_string(std::string_view raw)

      Parse a complete URI. Returns ``std::nullopt`` on any parse failure, including
      relative references (inputs without a scheme).

   .. cpp:function:: const std::string& scheme() const

      Scheme, lowercase-normalized.

   .. cpp:function:: const std::optional<Authority>& authority() const

      The parsed authority (``userinfo@host:port``), if this URI has a non-empty
      one. See :cpp:class:`URI::Authority`.

   .. cpp:function:: std::optional<std::string_view> raw_authority() const

      The raw (unparsed) authority component, if this URI included one. This
      distinguishes an empty authority (``"ldap:///CN=x"``, empty string here while
      :cpp:func:`authority` is ``std::nullopt``) from an absent one
      (``"mailto:user@example.com"``, ``std::nullopt`` for both). Equality comparison
      also distinguishes these two cases.

   .. cpp:function:: std::optional<std::reference_wrapper<const Host>> host() const

      The parsed host, if this URI has a non-empty authority.

   .. cpp:function:: const std::string& path() const

      The path component, preserved verbatim. In a URI with an authority, a
      non-empty path always begins with ``"/"``; without an authority the path is
      whatever followed the scheme (``"user@example.com"`` for
      ``"mailto:user@example.com"``). Empty if the parsed URI had no path (e.g.
      ``"http://example.com"`` or ``"http://example.com?q"``).

   .. cpp:function:: const std::optional<std::string>& query() const

      The query component, without the leading ``"?"``, or ``std::nullopt`` if no
      query component was present.

   .. cpp:function:: const std::optional<std::string>& fragment() const

      The fragment component, without the leading ``"#"``, or ``std::nullopt`` if no
      fragment component was present.

   .. cpp:function:: const std::string& original_input() const

      The original input string that this URI was parsed from.

   .. cpp:function:: static std::vector<URI> filter_scheme( \
                     std::string_view scheme, std::span<const URI> uris)

      Return the subset of *uris* whose scheme matches *scheme* (compared after
      lowercasing) and which contain a non-empty authority.

.. cpp:class:: URI::Authority

   The authority component of a URI: a validated DNS name, IPv4 literal, or IPv6
   literal, with an optional port and optional userinfo.

   .. cpp:type:: Host = std::variant<DNSName, IPv4Address, IPv6Address>

      Alternative types of the parsed host. Also accessible as :cpp:type:`URI::Host`.

   .. cpp:enum-class:: HostKind : uint8_t

      Tag for the alternative held by :cpp:type:`Host`. Members: ``DNS``, ``IPv4``, ``IPv6``.
      Also accessible as :cpp:type:`URI::HostKind`.

   .. cpp:function:: static std::optional<Authority> from_string(std::string_view raw)

      Parse a bare authority of the form ``"host[:port]"`` or ``"[ipv6][:port]"``
      (with optional ``"userinfo@"`` prefix). A port, if present, must be in
      ``[1, 65535]``, with no leading zeros. Returns ``std::nullopt`` for any
      parse failure.

   .. cpp:function:: const Host& host() const

      The parsed host, as one of :cpp:class:`DNSName`, :cpp:class:`IPv4Address`, or
      :cpp:class:`IPv6Address`.

   .. cpp:function:: HostKind host_kind() const

      Which alternative of :cpp:func:`host` is held.

   .. cpp:function:: std::string host_to_string() const

      The host as a string, in the canonical ``to_string`` form of the held
      alternative: DNS names are lowercased, and IPv6 addresses are in :rfc:`5952`
      form without surrounding brackets.

   .. cpp:function:: std::optional<uint16_t> port() const

      The port if present, or ``std::nullopt`` if it was absent.

   .. cpp:function:: const std::string& original_input() const

      The original input string that this authority was parsed from.

   .. cpp:function:: const std::optional<std::string>& userinfo() const

      The ``userinfo`` component, or ``std::nullopt`` if no ``"@"`` was present. Note
      that a present-but-empty userinfo (``"https://@example.com/"``) is represented as
      an empty string, which allows it to be distinguished from the absent case.
