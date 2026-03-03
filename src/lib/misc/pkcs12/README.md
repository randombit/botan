# PKCS#12 Support in Botan

This document describes how to use Botan's PKCS#12 (PFX) functionality from the command line.

## Overview

PKCS#12 is a binary format for storing a private key and its associated certificate chain in a single encrypted file. It's commonly used for:
- Exporting certificates from browsers
- Importing certificates into applications
- Transferring credentials between systems

## Prerequisites

Before creating a PKCS#12 file, you need:
1. A private key (RSA, ECDSA, etc.)
2. A certificate (self-signed or CA-signed)
3. Optionally, CA certificate chain

## CLI Commands

> **Note (Windows PowerShell):** PowerShell has encoding issues with binary output. Use `--output=` options when available, or use `cmd /c "command > file"` for shell redirection.

### 1. Generate a Private Key

```powershell
# Generate RSA 2048-bit key
cmd /c ".\botan-cli.exe keygen --algo=RSA --params=2048 > private_key.pem"

# Generate RSA 4096-bit key
cmd /c ".\botan-cli.exe keygen --algo=RSA --params=4096 > private_key.pem"

# Generate ECDSA key with P-256 curve
cmd /c ".\botan-cli.exe keygen --algo=ECDSA --params=secp256r1 > private_key.pem"

# Generate ECDSA key with P-384 curve
cmd /c ".\botan-cli.exe keygen --algo=ECDSA --params=secp384r1 > private_key.pem"

# Generate encrypted private key
cmd /c ".\botan-cli.exe keygen --algo=RSA --params=2048 --passphrase=mypassword > private_key_encrypted.pem"
```

### 2. Create a Self-Signed Certificate

```powershell
# Basic self-signed certificate (valid for 365 days)
cmd /c ".\botan-cli.exe gen_self_signed private_key.pem \"CN=My Certificate\" --ca > cert.pem"

# With more attributes
cmd /c ".\botan-cli.exe gen_self_signed private_key.pem \"CN=My Certificate,O=My Organization,C=US\" --ca > cert.pem"

# With custom validity period (days)
cmd /c ".\botan-cli.exe gen_self_signed private_key.pem \"CN=My Certificate\" --ca --days=730 > cert.pem"

# With SHA-256 signature (default)
cmd /c ".\botan-cli.exe gen_self_signed private_key.pem \"CN=My Certificate\" --ca --hash=SHA-256 > cert.pem"

# With SHA-384 signature
cmd /c ".\botan-cli.exe gen_self_signed private_key.pem \"CN=My Certificate\" --ca --hash=SHA-384 > cert.pem"
```

### 3. Create a Certificate Signing Request (CSR)

```powershell
# Generate CSR
cmd /c ".\botan-cli.exe gen_pkcs10 private_key.pem \"CN=My Certificate,O=My Organization\" > request.csr"

# With encrypted private key
cmd /c ".\botan-cli.exe gen_pkcs10 private_key_encrypted.pem \"CN=My Certificate\" --key-pass=mypassword > request.csr"
```

### 4. Sign a Certificate (as CA)

```powershell
# Sign a CSR with CA key
cmd /c ".\botan-cli.exe sign_cert ca_key.pem ca_cert.pem request.csr > signed_cert.pem"

# With custom validity
cmd /c ".\botan-cli.exe sign_cert ca_key.pem ca_cert.pem request.csr --days=365 > signed_cert.pem"
```

### 5. Create PKCS#12 File

```powershell
# Basic PKCS#12 creation (uses PBE-SHA1-3DES for compatibility)
.\botan-cli.exe pkcs12_export --pass=mypassword --output=output.pfx private_key.pem cert.pem

# With friendly name
.\botan-cli.exe pkcs12_export --pass=mypassword --friendly-name="My Certificate" --output=output.pfx private_key.pem cert.pem

# With CA certificate chain
.\botan-cli.exe pkcs12_export --pass=mypassword --output=output.pfx private_key.pem cert.pem ca_intermediate.pem ca_root.pem

# Using modern PBES2-AES256 encryption (more secure)
.\botan-cli.exe pkcs12_export --pass=mypassword --use-pbes2 --output=output.pfx private_key.pem cert.pem

# With encrypted input private key
.\botan-cli.exe pkcs12_export --pass=pfxpassword --key-pass=keypassword --output=output.pfx private_key_encrypted.pem cert.pem

# With custom KDF iterations (higher = slower but more secure)
.\botan-cli.exe pkcs12_export --pass=mypassword --iterations=10000 --output=output.pfx private_key.pem cert.pem
```

### 6. View PKCS#12 Information

```powershell
# Display PKCS#12 contents
.\botan-cli.exe pkcs12_info --pass=mypassword input.pfx

# Example output:
# PKCS#12 File: input.pfx
# =====================================
#
# Friendly Name: My Certificate
#
# Private Key:
#   Algorithm: RSA
#   Key Size: 2048 bits
#
# End-Entity Certificate:
#   Subject: CN="My Certificate",O="My Organization",C="US"
#   Issuer: CN="My CA",O="My Organization",C="US"
#   Serial: 01A2B3C4D5E6F7...
#   Not Before: 2026/01/01 00:00:00 UTC
#   Not After: 2027/01/01 00:00:00 UTC
#   SHA-256 Fingerprint: AB:CD:EF:...
#
# CA Certificates (1):
#   [1] Subject: CN="My CA",O="My Organization",C="US"
#       Issuer: CN="My CA",O="My Organization",C="US"
#       SHA-256 Fingerprint: 12:34:56:...
```

### 7. Extract from PKCS#12 (Import)

```powershell
# Extract private key to PEM format
cmd /c ".\botan-cli.exe pkcs12_import --pass=pfxpassword --export-key input.pfx > private_key.pem"

# Extract private key with encryption
cmd /c ".\botan-cli.exe pkcs12_import --pass=pfxpassword --export-key --key-pass=newkeypassword input.pfx > private_key_encrypted.pem"

# Extract end-entity certificate
cmd /c ".\botan-cli.exe pkcs12_import --pass=pfxpassword --export-cert input.pfx > cert.pem"

# Extract CA chain certificates
cmd /c ".\botan-cli.exe pkcs12_import --pass=pfxpassword --export-chain input.pfx > ca_chain.pem"
```

## Complete Example: Create and Use PKCS#12

```powershell
# Step 1: Generate a private key
cmd /c ".\botan-cli.exe keygen --algo=RSA --params=2048 > mykey.pem"

# Step 2: Create a self-signed certificate
cmd /c ".\botan-cli.exe gen_self_signed mykey.pem \"CN=Test Certificate,O=Test Org,C=US\" --ca > mycert.pem"

# Step 3: Create PKCS#12 file (use --output to avoid encoding issues)
.\botan-cli.exe pkcs12_export --pass=test123 --friendly-name="Test Certificate" --output=test.pfx mykey.pem mycert.pem

# Step 4: Verify the PKCS#12 file
.\botan-cli.exe pkcs12_info --pass=test123 test.pfx

# Step 5: Extract the key and certificate back
cmd /c ".\botan-cli.exe pkcs12_import --pass=test123 --export-key test.pfx > extracted_key.pem"
cmd /c ".\botan-cli.exe pkcs12_import --pass=test123 --export-cert test.pfx > extracted_cert.pem"
```

## Supported Encryption Algorithms

### Key Encryption (for private key in PKCS#12)
| Algorithm | Flag | Security | Compatibility |
|-----------|------|----------|---------------|
| PBE-SHA1-3DES | (default) | Legacy | Excellent |
| PBE-SHA1-2DES | - | Weak | Good |
| PBE-SHA1-RC2-40 | - | Very Weak | Legacy only |
| PBE-SHA1-RC2-128 | - | Weak | Legacy only |
| PBES2-SHA256-AES256 | `--use-pbes2` | Strong | Modern apps |
| PBES2-SHA256-AES128 | - | Strong | Modern apps |

### Certificate Encryption
By default, certificates in PKCS#12 files are stored unencrypted (wrapped in plaintext ContentInfo). The `pkcs12_export` command uses PBE-SHA1-3DES for maximum compatibility.

## Parsing Third-Party PKCS#12 Files

Botan can parse PKCS#12 files created by other tools:

```powershell
# Parse OpenSSL-created PFX
.\botan-cli.exe pkcs12_info --pass=password openssl_created.pfx

# Parse Windows-exported PFX  
.\botan-cli.exe pkcs12_info --pass=password windows_exported.pfx

# Parse Java keystore exported PFX
.\botan-cli.exe pkcs12_info --pass=password java_keystore.pfx
```

### Supported MAC Algorithms
- HMAC-SHA-1 (most common)
- HMAC-SHA-256 (modern)

### Supported PBE Algorithms (for parsing)
- PBE-SHA1-3DES (most common)
- PBE-SHA1-2DES
- PBE-SHA1-RC2-40 (requires RC2 module)
- PBE-SHA1-RC2-128 (requires RC2 module)
- PBES2 with AES-128/256 and SHA-256 PBKDF2

## Programmatic API

For programmatic usage, see the header file:

```cpp
#include <botan/pkcs12.h>

// Parse PKCS#12
auto pfx_data = Botan::PKCS12::load("file.pfx", "password");
auto key = pfx_data.private_key();
auto cert = pfx_data.certificate();
auto chain = pfx_data.ca_certificates();

// Create PKCS#12
Botan::PKCS12_Options options;
options.password = "password";
options.friendly_name = "My Key";
auto pfx_bytes = Botan::PKCS12::create(*key, cert, chain, options, rng);
```

## Security Recommendations

1. **Use strong passwords** - PKCS#12 files are only as secure as their passwords
2. **Prefer PBES2-AES256** - Use `--use-pbes2` for new files when compatibility permits
3. **Use high iteration counts** - `--iterations=10000` or higher for sensitive keys
4. **Avoid RC2** - RC2 algorithms are cryptographically weak, only use for legacy compatibility
5. **Protect PFX files** - Even encrypted, treat them as sensitive credentials
