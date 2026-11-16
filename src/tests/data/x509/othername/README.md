# otherName test certificates

Certificates carrying `otherName` entries in the SubjectAlternativeName,
IssuerAlternativeName and NameConstraints extensions. They exercise the
otherName support of the `botan_x509_general_name_t` FFI API
(`src/tests/test_ffi.cpp`) and of the Python binding
(`src/scripts/test_python.py`). The tests only parse these certificates,
they are never path validated.

All certificates are self-signed (P-256, ECDSA with SHA-256) and valid from
2026-01-01 to 2035-12-30. They were generated with OpenSSL 3.6.1 by running

    ./src/scripts/dev_tools/gen_othername_testdata.sh

from the repository root. The script embeds the OpenSSL configuration of
every certificate. Re-running it creates fresh keys, so the public keys and
signatures change, while the extension contents (and therefore the values the
tests expect) stay the same.

## Contents

The type-ids below `1.3.6.1.4.1.25258.10000` (an arc below Botan's private
enterprise number) carry no meaning. `1.3.6.1.4.1.311.20.2.3` is the
Microsoft User Principal Name (UPN), which is registered in Botan under the
name "Microsoft UPN".

| File                   | Extension | Entries |
|------------------------|-----------|---------|
| `msupn-san.pem`        | SAN       | `DNS:www.example.com`, `email:alice@example.com`, otherName UPN with UTF8String `alice@corp.example.com` |
| `string-utf8.pem`      | SAN       | otherName `...10000.1` with UTF8String `Jürgen@example.com` (non-ASCII) |
| `string-ia5.pem`       | SAN       | otherName `...10000.2` with IA5String `ia5@example.com` |
| `string-printable.pem` | SAN       | otherName `...10000.3` with PrintableString `Printable Name 42` |
| `string-visible.pem`   | SAN       | otherName `...10000.4` with VisibleString `Visible String!` |
| `string-numeric.pem`   | SAN       | otherName `...10000.5` with NumericString `0123456789` |
| `string-bmp.pem`       | SAN       | otherName `...10000.6` with BMPString `bmp` |
| `string-universal.pem` | SAN       | otherName `...10000.7` with UniversalString `uni` |
| `string-teletex.pem`   | SAN       | otherName `...10000.8` with TeletexString `teletex` |
| `non-string.pem`       | SAN       | otherName `...10000.10` with `SEQUENCE { INTEGER 42 }`, otherName `...10000.11` with `OCTET STRING DEADBEEF` |
| `multi.pem`            | SAN       | `DNS:multi.example.com`, `email:multi@example.com`, `IP:192.0.2.1`, otherName UPN with UTF8String `multi@corp.example.com`, otherName `...10000.2` with IA5String `ia5@example.com`, otherName `...10000.6` with BMPString `bmp`, otherName `...10000.10` with `SEQUENCE { INTEGER 42 }` |
| `ian.pem`              | SAN, IAN  | SAN `DNS:www.example.com`; IAN `DNS:ca.example.com`, otherName UPN with UTF8String `issuer@corp.example.com` |
| `nc-excluded.pem`      | NC        | CA certificate; permitted `DNS:example.com`, permitted otherName `...10000.2` with IA5String `permitted@example.com`, excluded otherName UPN with UTF8String `excluded@corp.example.com` |
| `edge-values.pem`      | SAN       | otherName `...10000.20` with an empty UTF8String, otherName `...10000.21` with a UTF8String of 3000 `x` |

## Expected values

The raw inner value of an otherName is the complete TLV inside the
`[0] EXPLICIT` tag. The values below were read off the output of

    openssl asn1parse -in <file> -strparse <offset of the extension value> -i

| File                   | type-id                       | inner value (hex) |
|------------------------|-------------------------------|-------------------|
| `msupn-san.pem`        | `1.3.6.1.4.1.311.20.2.3`      | `0C16616C69636540636F72702E6578616D706C652E636F6D` |
| `string-utf8.pem`      | `1.3.6.1.4.1.25258.10000.1`   | `0C134AC3BC7267656E406578616D706C652E636F6D` |
| `string-ia5.pem`       | `1.3.6.1.4.1.25258.10000.2`   | `160F696135406578616D706C652E636F6D` |
| `string-printable.pem` | `1.3.6.1.4.1.25258.10000.3`   | `13115072696E7461626C65204E616D65203432` |
| `string-visible.pem`   | `1.3.6.1.4.1.25258.10000.4`   | `1A0F56697369626C6520537472696E6721` |
| `string-numeric.pem`   | `1.3.6.1.4.1.25258.10000.5`   | `120A30313233343536373839` |
| `string-bmp.pem`       | `1.3.6.1.4.1.25258.10000.6`   | `1E060062006D0070` |
| `string-universal.pem` | `1.3.6.1.4.1.25258.10000.7`   | `1C0C000000750000006E00000069` |
| `string-teletex.pem`   | `1.3.6.1.4.1.25258.10000.8`   | `140774656C65746578` |
| `non-string.pem`       | `1.3.6.1.4.1.25258.10000.10`  | `300302012A` |
| `non-string.pem`       | `1.3.6.1.4.1.25258.10000.11`  | `0404DEADBEEF` |
| `multi.pem`            | `1.3.6.1.4.1.311.20.2.3`      | `0C166D756C746940636F72702E6578616D706C652E636F6D` |
| `multi.pem`            | `1.3.6.1.4.1.25258.10000.2`   | `160F696135406578616D706C652E636F6D` |
| `multi.pem`            | `1.3.6.1.4.1.25258.10000.6`   | `1E060062006D0070` |
| `multi.pem`            | `1.3.6.1.4.1.25258.10000.10`  | `300302012A` |
| `ian.pem`              | `1.3.6.1.4.1.311.20.2.3`      | `0C1769737375657240636F72702E6578616D706C652E636F6D` |
| `nc-excluded.pem`      | `1.3.6.1.4.1.25258.10000.2`   | `16157065726D6974746564406578616D706C652E636F6D` |
| `nc-excluded.pem`      | `1.3.6.1.4.1.311.20.2.3`      | `0C196578636C7564656440636F72702E6578616D706C652E636F6D` |
| `edge-values.pem`      | `1.3.6.1.4.1.25258.10000.20`  | `0C00` |
| `edge-values.pem`      | `1.3.6.1.4.1.25258.10000.21`  | `0C820BB8` followed by 3000 times `78` |
