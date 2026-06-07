#!/usr/bin/env python3

"""
Run the Wycheproof tests

This script is run against a git checkout of Wycheproof

(C) 2026 Jack Lloyd
(C) 2026 Rene Meusel, Rohde & Schwarz Cybersecurity

Botan is released under the Simplified BSD License (see license.txt)
"""

import argparse
import base64
import binascii
import ctypes
import io
import json
import multiprocessing
import os
import subprocess
import sys
import traceback
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import botan3 as botan

# ---- Framework ----


class TestSkip(Exception):
    """Raised by a handler to skip a test vector."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class TestFailure(Exception):
    """Raised by a handler when a test vector fails.

    Can be constructed with either:
      - A dict of field_name -> value for .vec-style output
      - A plain string message
    """

    def __init__(self, fields_or_message):
        if isinstance(fields_or_message, dict):
            self.fields = fields_or_message
            msg = "; ".join(f"{k}={v}" for k, v in fields_or_message.items())
        else:
            self.fields = None
            msg = str(fields_or_message)
        super().__init__(msg)


class FixedOutputRNG(botan.RandomNumberGenerator):
    def __init__(self, entropy_pool: bytes = b""):
        super().__init__(
            "custom", get_callback=self._get, add_entropy_callback=self._add_entropy
        )
        self._entropy_pool = entropy_pool

    def _get(self, length: int) -> bytes:
        if length > len(self._entropy_pool):
            raise ValueError("Not enough entropy in pool")
        entropy = self._entropy_pool[:length]
        self._entropy_pool = self._entropy_pool[length:]
        return entropy

    def _add_entropy(self, data: bytes) -> None:
        self._entropy_pool += data


class NullRNG(botan.RandomNumberGenerator):
    """An RNG that raises an exception if it is used."""

    def __init__(self):
        super().__init__(
            "custom", get_callback=self._get, add_entropy_callback=self._add_entropy
        )

    def _get(self, length: int) -> bytes:
        raise botan.BotanException("Unexpected request to get entropy from RNG", rc=-23)

    def _add_entropy(self, data: bytes) -> None:
        raise botan.BotanException("Unexpected request to add entropy to RNG", rc=-23)


class _Registry:
    def __init__(self):
        self._handlers: dict[str, Callable] = {}
        self._ignored: set[str] = set()

    def register(self, algorithm: str, handler: Callable) -> None:
        if algorithm in self._handlers:
            raise RuntimeError(
                f"Algorithm {algorithm!r} already registered by "
                f"{self._handlers[algorithm].__name__}, "
                f"cannot also register {handler.__name__}"
            )
        self._handlers[algorithm] = handler

    def get(self, algorithm: str) -> Callable | None:
        return self._handlers.get(algorithm)

    def ignore(self, *algorithms: str) -> None:
        for algo in algorithms:
            if algo in self._handlers:
                raise RuntimeError(f"Algorithm {algo!r} is both registered and ignored")
            self._ignored.add(algo)

    def is_ignored(self, algorithm: str) -> bool:
        return algorithm in self._ignored


_registry = _Registry()


def register(*algorithms: str):
    """Decorator to register a handler for one or more Wycheproof algorithm values."""

    def decorator(func):
        for algo in algorithms:
            _registry.register(algo, func)
        return func

    return decorator


@dataclass
class _FileResult:
    """Result of processing a single JSON file."""

    filename: str
    category: str  # "claimed", "unclaimed", "ignored", "no_algorithm"
    algorithm: str | None = None
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    skip_reasons: dict[str, int] = field(default_factory=dict)
    output: str = ""


def _process_file(args: tuple[str, int]) -> _FileResult:
    json_path_str, verbosity = args
    json_path = Path(json_path_str)
    filename = json_path.name

    data = json.loads(json_path.read_bytes())
    algorithm = data.get("algorithm")

    if algorithm is None:
        return _FileResult(filename, "no_algorithm")
    if _registry.is_ignored(algorithm):
        return _FileResult(filename, "ignored", algorithm=algorithm)
    handler = _registry.get(algorithm)
    if handler is None:
        return _FileResult(filename, "unclaimed", algorithm=algorithm)

    result = _FileResult(filename, "claimed", algorithm=algorithm)
    out = io.StringIO()

    if verbosity >= 2:
        print(f"{filename} ({algorithm}):", file=out)

    for group in data["testGroups"]:
        for test in group["tests"]:
            tc_id = test.get("tcId", "?")
            try:
                handler(data, group, test)
                result.passed += 1
                if verbosity >= 2:
                    print(f"  PASS: test {tc_id}", file=out)
            except TestSkip as e:
                result.skipped += 1
                reason = str(e)
                result.skip_reasons[reason] = result.skip_reasons.get(reason, 0) + 1
                if verbosity >= 2:
                    print(f"  SKIP: test {tc_id}: {reason}", file=out)
            except TestFailure as e:
                result.failed += 1
                print(f"\nFAIL: # Wycheproof test {tc_id} from {filename}", file=out)
                if e.fields:
                    for key, value in e.fields.items():
                        print(f"{key} = {value}", file=out)
                else:
                    print(f"  {e}", file=out)
            except Exception as e:
                result.errors += 1
                print(f"\nERROR: # Wycheproof test {tc_id} from {filename}", file=out)
                print(f"  {type(e).__name__}: {e}", file=out)
                print(traceback.format_exc(), file=out)

    result.output = out.getvalue()
    return result


def _git_rev(directory: str) -> str | None:
    """Return the git revision of a directory, or None if not a git repo."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass
    return None


def run(
    wycheproof_dir: str,
    verbosity: int = 1,
    jobs: int | None = None,
    filters: list[str] | None = None,
) -> int:
    """Main entry point. Returns 0 on success, 1 on failure."""
    tv_dir = Path(wycheproof_dir) / "testvectors_v1"
    if not tv_dir.is_dir():
        print(f"ERROR: {tv_dir} is not a directory")
        return 1

    wycheproof_rev = _git_rev(wycheproof_dir)

    json_paths = sorted(tv_dir.glob("*.json"))

    if filters:
        filters_lower = [f.lower() for f in filters]
        filtered = []
        for p in json_paths:
            if any(f in p.name.lower() for f in filters_lower):
                filtered.append(p)
                continue
            algo = json.loads(p.read_bytes()).get("algorithm", "")
            if any(f in algo.lower() for f in filters_lower):
                filtered.append(p)
        json_paths = filtered

    work = [(str(p), verbosity) for p in json_paths]

    if jobs == 1:
        file_results = [_process_file(item) for item in work]
    else:
        with multiprocessing.Pool(jobs) as pool:
            file_results = pool.map(_process_file, work)

    # Aggregate results and print buffered output
    passed = 0
    failed = 0
    errors = 0
    skipped = 0
    files_claimed = 0
    files_ignored = 0
    unclaimed: list[tuple[str, str]] = []
    no_algorithm: list[str] = []
    skip_reasons: Counter[str] = Counter()

    for fr in file_results:
        if fr.output:
            sys.stderr.write(fr.output)

        if fr.category == "no_algorithm":
            no_algorithm.append(fr.filename)
        elif fr.category == "ignored":
            files_ignored += 1
        elif fr.category == "unclaimed":
            unclaimed.append((fr.filename, fr.algorithm))
        else:
            files_claimed += 1
            passed += fr.passed
            failed += fr.failed
            errors += fr.errors
            skipped += fr.skipped
            for reason, count in fr.skip_reasons.items():
                skip_reasons[reason] += count

    # Print summary
    total_files = files_claimed + files_ignored + len(unclaimed) + len(no_algorithm)
    total_tests = passed + failed + errors + skipped

    print("Wycheproof Results")
    print("Botan version: %s" % (botan.version_string()))
    print("Wycheproof revision: %s" % (wycheproof_rev))

    print("Total %d Passed %d Failed %d Errors %d Skipped %d" % (total_tests, passed, failed, errors, skipped))

    print(
        f"Files: {total_files} total, {files_claimed} claimed, "
        f"{files_ignored} ignored, {len(unclaimed)} unclaimed",
    )

    if verbosity >= 1:
        if skip_reasons:
            print("\nSkipped tests (by reason):")
            for reason, count in skip_reasons.most_common():
                print(f"  {count}x: {reason}")

        if unclaimed:
            print(f"\nUnclaimed files ({len(unclaimed)}):")
            for filename, algorithm in unclaimed:
                print(f"  {filename} ({algorithm})")

        if no_algorithm:
            print(f"\nFiles without algorithm field ({len(no_algorithm)}):")
            for filename in no_algorithm:
                print(f"  {filename}")

    return 0 if (failed == 0 and errors == 0) else 1


# ---- Common utilities ----


def _from_hex(value: str) -> bytes:
    return binascii.unhexlify(value)


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (4 - len(s) % 4))


_CURVE_NAME_MAP = {
    "brainpoolP224r1": "brainpool224r1",
    "brainpoolP256r1": "brainpool256r1",
    "brainpoolP320r1": "brainpool320r1",
    "brainpoolP384r1": "brainpool384r1",
    "brainpoolP512r1": "brainpool512r1",
    "P-256": "secp256r1",
    "P-384": "secp384r1",
    "P-521": "secp521r1",
}

_HASH_NAME_MAP = {
    "SHA-1": "SHA-1",
    "SHA-224": "SHA-224",
    "SHA-256": "SHA-256",
    "SHA-384": "SHA-384",
    "SHA-512": "SHA-512",
    "SHA-512/256": "SHA-512-256",
    "SHA3-224": "SHA-3(224)",
    "SHA3-256": "SHA-3(256)",
    "SHA3-384": "SHA-3(384)",
    "SHA3-512": "SHA-3(512)",
    "SHAKE128": "SHAKE-128(256)",
    "SHAKE256": "SHAKE-256(512)",
}


# ---- AEAD handler ----

_AEAD_CIPHER_ALIASES = {
    "AES-GCM": "AES",
    "AES-CCM": "AES",
    "AEAD-AES-SIV-CMAC": "AES-SIV-CMAC",
    "ARIA-GCM": "ARIA",
    "ARIA-CCM": "ARIA",
    "CAMELLIA-CCM": "Camellia",
    "SEED-GCM": "SEED",
    "SEED-CCM": "SEED",
    "SM4-GCM": "SM4",
    "SM4-CCM": "SM4",
}


def _aead_algorithm(
    algorithm: str, key_size_bits: int, tag_size_bits: int | None, nonce_len: int
) -> str:
    tag_len_bytes = tag_size_bits // 8 if tag_size_bits is not None else None

    if algorithm in ("AEAD-AES-SIV-CMAC", "AES-SIV-CMAC"):
        return f"AES-{key_size_bits // 2}/SIV"
    if algorithm == "AES-EAX":
        return f"AES-{key_size_bits}/EAX"
    if algorithm in ("CHACHA20-POLY1305", "XCHACHA20-POLY1305"):
        return "ChaCha20Poly1305"

    cipher = _AEAD_CIPHER_ALIASES.get(algorithm)
    if cipher is None:
        raise ValueError(f"Unsupported AEAD algorithm: {algorithm}")

    if cipher in ("AES", "ARIA", "Camellia"):
        cipher = f"{cipher}-{key_size_bits}"

    if algorithm.endswith("GCM"):
        suffix = f"/GCM({tag_len_bytes})" if tag_len_bytes is not None else "/GCM"
        return f"{cipher}{suffix}"

    if algorithm.endswith("CCM"):
        l_val = 15 - nonce_len
        if tag_len_bytes is None:
            return f"{cipher}/CCM({l_val})"
        return f"{cipher}/CCM({tag_len_bytes},{l_val})"

    raise ValueError(f"Unhandled AEAD algorithm: {algorithm}")


def _aead_process(
    aead: botan.SymmetricCipher, iv: bytes, aad: bytes, data: bytes
) -> bytes:
    aead.set_assoc_data(aad)
    aead.start(iv)
    return aead.finish(data)


@register(
    "AES-GCM",
    "AES-CCM",
    "AES-EAX",
    "AEAD-AES-SIV-CMAC",
    "AES-SIV-CMAC",
    "ARIA-GCM",
    "ARIA-CCM",
    "CAMELLIA-CCM",
    "SEED-GCM",
    "SEED-CCM",
    "SM4-GCM",
    "SM4-CCM",
    "CHACHA20-POLY1305",
    "XCHACHA20-POLY1305",
)
def handle_aead(data: dict, group: dict, test: dict) -> None:
    algorithm = data["algorithm"]
    is_siv = algorithm in ("AEAD-AES-SIV-CMAC", "AES-SIV-CMAC")

    tag_size_bits = group.get("tagSize")
    key_size_bits = group.get("keySize")

    key = _from_hex(test["key"])
    iv = _from_hex(test.get("iv", ""))
    aad = _from_hex(test.get("aad", ""))
    msg = _from_hex(test["msg"])
    ct = _from_hex(test["ct"])
    tag = _from_hex(test["tag"]) if "tag" in test else b""
    expected_ct_tag = (tag + ct) if is_siv else (ct + tag)

    algo = _aead_algorithm(algorithm, key_size_bits, tag_size_bits, len(iv))

    def _fields(**extra):
        fields = {"Key": test["key"], "Msg": test["msg"]}
        if "iv" in test:
            fields["Nonce"] = test["iv"]
        if "aad" in test:
            fields["AD"] = test["aad"]
        fields["CT"] = test["ct"]
        if "tag" in test:
            fields["Tag"] = test["tag"]
        fields.update(extra)
        return fields

    if test["result"] == "valid":
        enc = botan.SymmetricCipher(algo, True)
        enc.set_key(key)
        enc_out = _aead_process(enc, iv, aad, msg)
        if enc_out != expected_ct_tag:
            raise TestFailure(_fields(ComputedCT=enc_out.hex()))

        dec = botan.SymmetricCipher(algo, False)
        dec.set_key(key)
        dec_out = _aead_process(dec, iv, aad, expected_ct_tag)
        if dec_out != msg:
            raise TestFailure(_fields(DecryptedMsg=dec_out.hex()))
    elif test["result"] in ("invalid", "acceptable"):
        try:
            dec = botan.SymmetricCipher(algo, False)
            dec.set_key(key)
            dec_out = _aead_process(dec, iv, aad, expected_ct_tag)
            if test["result"] == "invalid":
                raise TestFailure(
                    _fields(
                        DecryptedMsg=dec_out.hex(),
                        Note="Invalid AEAD test decrypted without authentication failure",
                    )
                )
            if test["result"] == "acceptable" and dec_out != msg:
                raise TestFailure(
                    _fields(
                        DecryptedMsg=dec_out.hex(),
                        Note="Acceptable test decrypted to wrong plaintext",
                    )
                )
        except botan.BotanException:
            pass
    else:
        raise TestFailure(f"Unknown test result: {test['result']}")


# ---- ECDH handler ----


@register("ECDH")
def handle_ecdh(_data: dict, group: dict, test: dict) -> None:
    group_type = group.get("type", "")
    if group_type not in (
        "EcdhTest",
        "EcdhEcpointTest",
        "EcdhPemTest",
        "EcdhWebcryptoTest",
    ):
        raise TestSkip(f"ECDH group type {group_type!r} not supported")

    curve = _CURVE_NAME_MAP.get(group["curve"], group["curve"])
    if not botan.ECGroup.supports_named_group(curve):
        raise TestSkip(f"Curve {curve} not supported in this build")

    try:
        if group_type == "EcdhPemTest":
            # PEM EC keys load as ECDSA by default; re-create as ECDH
            pem_key = botan.PrivateKey.load(test["private"].encode())
            priv_key = botan.PrivateKey.load_ecdh(curve, pem_key.get_field("x"))
        elif group_type == "EcdhWebcryptoTest":
            priv_d = int.from_bytes(_b64url_decode(test["private"]["d"]), "big")
            priv_key = botan.PrivateKey.load_ecdh(curve, botan.MPI(priv_d))
        else:
            priv_key = botan.PrivateKey.load_ecdh(
                curve, botan.MPI(test["private"], radix=16)
            )
    except botan.BotanException:
        if test["result"] != "valid":
            return
        raise

    if group_type == "EcdhEcpointTest":
        pub_raw = _from_hex(test["public"])
    elif group_type == "EcdhWebcryptoTest":
        if "InvalidPublic" in test.get("flags", []):
            raise TestSkip("JWK structural validation test")
        pub_x = _b64url_decode(test["public"]["x"])
        pub_y = _b64url_decode(test["public"]["y"])
        pub_raw = b"\x04" + pub_x + pub_y
    elif group_type == "EcdhPemTest":
        try:
            pub_key = botan.PublicKey.load(test["public"].encode())
        except botan.BotanException:
            if test["result"] != "valid":
                return
            raise
        if pub_key.used_explicit_encoding():
            if test["result"] not in ("invalid", "acceptable"):
                raise TestFailure(
                    {
                        "Curve": curve,
                        "Note": "Explicit curve encoding on valid test",
                    }
                )
            return
        pub_raw = pub_key.to_raw()
    else:
        try:
            pub_key = botan.PublicKey.load(_from_hex(test["public"]))
        except botan.BotanException:
            if test["result"] != "valid":
                return
            raise

        if pub_key.used_explicit_encoding():
            if test["result"] not in ("invalid", "acceptable"):
                raise TestFailure(
                    {
                        "Curve": curve,
                        "Private": test["private"],
                        "Public": test["public"],
                        "Note": "Explicit curve encoding on valid test",
                    }
                )
            return
        pub_raw = pub_key.to_raw()

    try:
        ka = botan.PKKeyAgreement(priv_key, "Raw")
        shared_secret = ka.agree(pub_raw, 0, b"")
    except botan.BotanException:
        if test["result"] != "valid":
            return
        raise

    if test["result"] not in ("valid", "acceptable"):
        raise TestFailure(
            {
                "Curve": curve,
                "Private": test["private"],
                "Public": test["public"],
                "Shared": shared_secret.hex(),
                "Note": "Invalid test case produced a shared secret",
            }
        )

    expected = _from_hex(test["shared"])
    if shared_secret != expected:
        raise TestFailure(
            {
                "Curve": curve,
                "Private": test["private"],
                "Public": test["public"],
                "Shared": test["shared"],
                "ComputedShared": shared_secret.hex(),
            }
        )


# ---- ECDSA handler ----


@register("ECDSA")
def handle_ecdsa(_data: dict, group: dict, test: dict) -> None:
    botan_hash = _map_hash(group["sha"])
    curve = _CURVE_NAME_MAP.get(
        group["publicKey"]["curve"], group["publicKey"]["curve"]
    )
    if not botan.ECGroup.supports_named_group(curve):
        raise TestSkip(f"Curve {curve} not supported in this build")

    try:
        pub_key = botan.PublicKey.load(_from_hex(group["publicKeyDer"]))
    except botan.BotanException:
        if test["result"] != "valid":
            return
        raise

    group_type = group["type"]
    if group_type == "EcdsaBitcoinVerify":
        raise TestSkip("Bitcoin variant of ECDSA is not supported")

    if group_type in ("EcdsaVerify", "EcdsaBitcoinVerify"):
        use_der = True
    elif group_type == "EcdsaP1363Verify":
        use_der = False
    else:
        raise TestFailure(f"Unknown test group type: {group_type}")

    try:
        verifier = botan.PKVerify(pub_key, botan_hash, der=use_der)
        verifier.update(_from_hex(test["msg"]))
        valid = verifier.check_signature(_from_hex(test["sig"]))
    except botan.BotanException:
        if test["result"] != "valid":
            return
        raise

    expected_valid = test["result"] == "valid"
    if valid != expected_valid:
        raise TestFailure(
            {
                "Curve": curve,
                "Hash": group["sha"],
                "Msg": test["msg"],
                "Sig": test["sig"],
                "Expected": "valid" if expected_valid else "invalid",
                "Got": "valid" if valid else "invalid",
            }
        )


# ---- HKDF handler ----

_HKDF_ALIASES = {
    "HKDF-SHA-1": "HKDF(SHA-1)",
    "HKDF-SHA-256": "HKDF(SHA-256)",
    "HKDF-SHA-384": "HKDF(SHA-384)",
    "HKDF-SHA-512": "HKDF(SHA-512)",
}


@register("HKDF-SHA-1", "HKDF-SHA-256", "HKDF-SHA-384", "HKDF-SHA-512")
def handle_hkdf(data: dict, _group: dict, test: dict) -> None:
    algo = _HKDF_ALIASES.get(data["algorithm"])
    if algo is None:
        raise ValueError(f"Unsupported HKDF algorithm: {data['algorithm']}")

    ikm = _from_hex(test["ikm"])
    salt = _from_hex(test["salt"])
    info = _from_hex(test["info"])
    size = test["size"]
    expected = _from_hex(test["okm"])

    try:
        actual = botan.kdf(algo, ikm, size, salt, info)
    except botan.BotanException:
        if test["result"] in ("invalid", "acceptable"):
            return
        raise

    if test["result"] == "valid":
        if actual != expected:
            raise TestFailure(
                {
                    "IKM": test["ikm"],
                    "Salt": test["salt"],
                    "Info": test["info"],
                    "Size": str(size),
                    "OKM": test["okm"],
                    "ComputedOKM": actual.hex(),
                }
            )
    elif test["result"] == "invalid":
        if actual == expected:
            raise TestFailure(
                {
                    "IKM": test["ikm"],
                    "Salt": test["salt"],
                    "Info": test["info"],
                    "Size": str(size),
                    "OKM": test["okm"],
                    "Note": "Invalid test produced matching output",
                }
            )
    elif test["result"] == "acceptable":
        pass
    else:
        raise TestFailure(f"Unknown test result: {test['result']}")


# ---- PBKDF2 handler ----

_PBKDF2_ALIASES = {
    "PBKDF2-HMACSHA1": "PBKDF2(SHA-1)",
    "PBKDF2-HMACSHA224": "PBKDF2(SHA-224)",
    "PBKDF2-HMACSHA256": "PBKDF2(SHA-256)",
    "PBKDF2-HMACSHA384": "PBKDF2(SHA-384)",
    "PBKDF2-HMACSHA512": "PBKDF2(SHA-512)",
}


@register(
    "PBKDF2-HMACSHA1",
    "PBKDF2-HMACSHA224",
    "PBKDF2-HMACSHA256",
    "PBKDF2-HMACSHA384",
    "PBKDF2-HMACSHA512",
)
def handle_pbkdf2(data: dict, _group: dict, test: dict) -> None:
    algo = _PBKDF2_ALIASES[data["algorithm"]]
    password = _from_hex(test["password"])
    salt = _from_hex(test["salt"])
    iterations = test["iterationCount"]
    dk_len = test["dkLen"]
    expected = _from_hex(test["dk"])

    try:
        out_buf = ctypes.create_string_buffer(dk_len)
        # pylint: disable=protected-access
        raw_algo = botan._ctype_str(algo)
        # pylint: disable=protected-access
        botan._DLL.botan_pwdhash(
            raw_algo,
            iterations,
            0,
            0,
            out_buf,
            dk_len,
            password,
            len(password),
            salt,
            len(salt),
        )
        actual = out_buf.raw
    except botan.BotanException:
        if test["result"] in ("invalid", "acceptable"):
            return
        raise

    if test["result"] == "valid":
        if actual != expected:
            raise TestFailure(
                {
                    "Password": test["password"],
                    "Salt": test["salt"],
                    "Iterations": str(iterations),
                    "DkLen": str(dk_len),
                    "DK": test["dk"],
                    "ComputedDK": actual.hex(),
                }
            )
    elif test["result"] == "invalid":
        if actual == expected:
            raise TestFailure(
                {
                    "Password": test["password"],
                    "Salt": test["salt"],
                    "Iterations": str(iterations),
                    "DkLen": str(dk_len),
                    "DK": test["dk"],
                    "Note": "Invalid test produced matching output",
                }
            )
    elif test["result"] == "acceptable":
        pass
    else:
        raise TestFailure(f"Unknown test result: {test['result']}")


# ---- MAC handler ----

_MAC_ALGORITHMS = {
    "HMACSHA1": "HMAC(SHA-1)",
    "HMACSHA224": "HMAC(SHA-224)",
    "HMACSHA256": "HMAC(SHA-256)",
    "HMACSHA384": "HMAC(SHA-384)",
    "HMACSHA512": "HMAC(SHA-512)",
    "HMACSHA3-224": "HMAC(SHA-3(224))",
    "HMACSHA3-256": "HMAC(SHA-3(256))",
    "HMACSHA3-384": "HMAC(SHA-3(384))",
    "HMACSHA3-512": "HMAC(SHA-3(512))",
    "HMACSM3": "HMAC(SM3)",
    "HMACSHA512/256": "HMAC(SHA-512-256)",
    "SipHash-1-3": "SipHash(1,3)",
    "SipHash-2-4": "SipHash(2,4)",
    "SipHash-4-8": "SipHash(4,8)",
    "KMAC128": "KMAC-128",
    "KMAC256": "KMAC-256",
}

_CMAC_CIPHERS = {
    "AES-CMAC": "AES",
    "ARIA-CMAC": "ARIA",
    "CAMELLIA-CMAC": "Camellia",
}


def _mac_algorithm(
    algorithm: str, key_size_bits: int | None, tag_size_bits: int | None
) -> str:
    if algorithm == "AES-GMAC":
        if key_size_bits is None:
            raise ValueError("AES-GMAC requires a key size")
        return f"GMAC(AES-{key_size_bits})"
    if algorithm.startswith("KMAC"):
        if tag_size_bits is None:
            raise ValueError("KMAC requires a tag size")
        return f"{_MAC_ALGORITHMS[algorithm]}({tag_size_bits})"
    if algorithm in _CMAC_CIPHERS:
        if key_size_bits is None:
            raise ValueError(f"{algorithm} requires a key size")
        return f"CMAC({_CMAC_CIPHERS[algorithm]}-{key_size_bits})"
    return _MAC_ALGORITHMS[algorithm]


@register(
    "HMACSHA1",
    "HMACSHA224",
    "HMACSHA256",
    "HMACSHA384",
    "HMACSHA512",
    "HMACSHA3-224",
    "HMACSHA3-256",
    "HMACSHA3-384",
    "HMACSHA3-512",
    "HMACSM3",
    "HMACSHA512/256",
    "SipHash-1-3",
    "SipHash-2-4",
    "SipHash-4-8",
    "AES-GMAC",
    "KMAC128",
    "KMAC256",
    "AES-CMAC",
    "ARIA-CMAC",
    "CAMELLIA-CMAC",
)
def handle_mac(data: dict, group: dict, test: dict) -> None:
    key_size_bits = group.get("keySize")
    iv_size_bits = group.get("ivSize")
    tag_size_bits = group.get("tagSize")

    algo = _mac_algorithm(data["algorithm"], key_size_bits, tag_size_bits)

    try:
        mac = botan.MsgAuthCode(algo)
        mac.set_key(_from_hex(test["key"]))
    except botan.BotanException:
        if test["result"] != "valid":
            return
        raise

    if iv_size_bits is not None:
        mac.set_nonce(_from_hex(test["iv"]))
    mac.update(_from_hex(test["msg"]))

    final_mac = mac.final()
    actual_mac = (
        final_mac[: tag_size_bits // 8] if tag_size_bits is not None else final_mac
    )
    expected = _from_hex(test["tag"])

    if test["result"] == "valid":
        if actual_mac != expected:
            raise TestFailure(
                {
                    "Key": test["key"],
                    "Msg": test["msg"],
                    "Tag": test["tag"],
                    "ComputedTag": actual_mac.hex(),
                }
            )
    elif test["result"] == "invalid":
        if actual_mac == expected:
            raise TestFailure(
                {
                    "Key": test["key"],
                    "Msg": test["msg"],
                    "Tag": test["tag"],
                    "Note": "Invalid test produced matching MAC",
                }
            )
    elif test["result"] == "acceptable":
        pass
    else:
        raise TestFailure(f"Unknown test result: {test['result']}")


# ---- ML-DSA handler ----

_MLDSA_MODE_MAP = {
    "ML-DSA-44": "ML-DSA-4x4",
    "ML-DSA-65": "ML-DSA-6x5",
    "ML-DSA-87": "ML-DSA-8x7",
}


def _mldsa_sign_test(mldsa_mode: str, group: dict, test: dict) -> None:
    priv = None
    try:
        if "privateSeed" in group:
            priv = botan.PrivateKey.load_ml_dsa(
                mldsa_mode, _from_hex(group["privateSeed"])
            )
        # TODO: implement loading from expanded private key
    except botan.BotanException:
        if test["result"] == "invalid":
            return
        raise

    if priv is None:
        raise TestSkip("ML-DSA noseed (expanded private key) not yet supported")

    pub = priv.get_public_key()
    if "publicKey" in group and group["publicKey"] is not None:
        expected_pk = _from_hex(group["publicKey"])
        if pub.to_raw() != expected_pk:
            raise TestFailure(
                {
                    "Mode": mldsa_mode,
                    "PrivateSeed": group.get("privateSeed", ""),
                    "PublicKey": group["publicKey"],
                    "ComputedPublicKey": pub.to_raw().hex(),
                    "Note": "Deserialized public key does not match expected",
                }
            )

    try:
        if "rnd" in test:
            signer = botan.PKSign(priv, "Randomized")
            signer.update(_from_hex(test["msg"]))
            actual_sig = signer.finish(FixedOutputRNG(_from_hex(test["rnd"])))
        else:
            signer = botan.PKSign(priv, "Deterministic")
            signer.update(_from_hex(test["msg"]))
            actual_sig = signer.finish(NullRNG())
    except botan.BotanException:
        if test["result"] == "invalid":
            return
        raise

    expected_sig = _from_hex(test["sig"])
    if actual_sig != expected_sig:
        raise TestFailure(
            {
                "Mode": mldsa_mode,
                "Msg": test["msg"],
                "Sig": test["sig"],
                "ComputedSig": actual_sig.hex(),
            }
        )


def _mldsa_verify_test(mldsa_mode: str, group: dict, test: dict) -> None:
    try:
        pub = botan.PublicKey.load_ml_dsa(mldsa_mode, _from_hex(group["publicKey"]))
    except botan.BotanException:
        if test["result"] == "invalid":
            return
        raise

    verifier = botan.PKVerify(pub, "")
    verifier.update(_from_hex(test["msg"]))
    valid = verifier.check_signature(_from_hex(test["sig"]))

    expected_valid = test["result"] == "valid"
    if valid != expected_valid:
        raise TestFailure(
            {
                "Mode": mldsa_mode,
                "Msg": test["msg"],
                "Sig": test["sig"],
                "Expected": "valid" if expected_valid else "invalid",
                "Got": "valid" if valid else "invalid",
            }
        )


@register("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
def handle_mldsa(data: dict, group: dict, test: dict) -> None:
    ctx = test.get("ctx")
    if ctx is not None and ctx != "":
        raise TestSkip("ML-DSA ctx not supported")

    if "msg" not in test or ("flags" in test and "Internal" in test["flags"]):
        raise TestSkip("ML-DSA's Sign_internal interface is not exposed")

    mldsa_mode = _MLDSA_MODE_MAP.get(
        data.get("algorithm", ""), data.get("algorithm", "")
    )
    group_type = group.get("type")

    if group_type == "MlDsaSign":
        _mldsa_sign_test(mldsa_mode, group, test)
    elif group_type == "MlDsaVerify":
        _mldsa_verify_test(mldsa_mode, group, test)
    else:
        raise TestFailure(f"Unknown test group type: {group_type}")


# ---- ML-KEM handler ----


@register("ML-KEM")
def handle_mlkem(_data: dict, group: dict, test: dict) -> None:
    mlkem_mode = group["parameterSet"]

    group_type = group.get("type", "")
    if group_type == "MLKEMDecapsValidationTest":
        raise TestSkip("ML-KEM semi-expanded decapsulation not yet supported")

    priv = None
    pub = None

    if "seed" in test:
        try:
            priv = botan.PrivateKey.load_ml_kem(mlkem_mode, _from_hex(test["seed"]))
        except botan.BotanException:
            if test["result"] == "invalid":
                return
            raise
        pub = priv.get_public_key()

    if "ek" in test:
        expected_ek = _from_hex(test["ek"])
        if pub is None:
            try:
                pub = botan.PublicKey.load_ml_kem(mlkem_mode, expected_ek)
            except botan.BotanException:
                if test["result"] == "invalid":
                    return
                raise

        if pub.to_raw() != expected_ek:
            raise TestFailure(
                {
                    "Mode": mlkem_mode,
                    "Seed": test.get("seed", ""),
                    "EK": test["ek"],
                    "ComputedEK": pub.to_raw().hex(),
                }
            )

    if not pub:
        raise ValueError("No public key available in this test vector")

    if "dk" in test:
        try:
            expected_dk = _from_hex(test["dk"])
            priv2 = botan.PrivateKey.load_ml_kem(mlkem_mode, expected_dk)
            # TODO: currently we cannot export the expanded private key via the python API
            if priv2.to_raw() != expected_dk:
                raise TestFailure(
                    {
                        "Mode": mlkem_mode,
                        "DK": test["dk"],
                        "ComputedDK": priv2.to_raw().hex(),
                    }
                )
            if priv2.get_public_key().to_raw() != pub.to_raw():
                raise TestFailure(
                    {
                        "Mode": mlkem_mode,
                        "DK": test["dk"],
                        "Note": "Private key's public key does not match expected",
                    }
                )
        except botan.BotanException:
            if test["result"] in ("invalid", "acceptable"):
                return
            raise

    if "c" in test and "K" in test:
        expected_k = _from_hex(test["K"])
        expected_c = _from_hex(test["c"])

        if "m" in test:
            rng = FixedOutputRNG(_from_hex(test["m"]))
            kem_e = botan.KemEncrypt(pub, "Raw")
            actual_k, actual_c = kem_e.create_shared_key(rng, b"", len(expected_k))
            if actual_k != expected_k:
                raise TestFailure(
                    {
                        "Mode": mlkem_mode,
                        "K": test["K"],
                        "ComputedK": actual_k.hex(),
                    }
                )
            if actual_c != expected_c:
                raise TestFailure(
                    {
                        "Mode": mlkem_mode,
                        "C": test["c"],
                        "ComputedC": actual_c.hex(),
                    }
                )

        if priv is not None:
            kem_d = botan.KemDecrypt(priv, "Raw")
            try:
                actual_k = kem_d.decrypt_shared_key(b"", len(expected_k), expected_c)
            except botan.BotanException:
                if test["result"] in ("invalid", "acceptable"):
                    return
                raise

            if test["result"] == "valid":
                if actual_k != expected_k:
                    raise TestFailure(
                        {
                            "Mode": mlkem_mode,
                            "K": test["K"],
                            "C": test["c"],
                            "ComputedK": actual_k.hex(),
                        }
                    )
            elif test["result"] == "invalid":
                if actual_k == expected_k:
                    raise TestFailure(
                        {
                            "Mode": mlkem_mode,
                            "K": test["K"],
                            "C": test["c"],
                            "Note": "Invalid test produced matching shared key",
                        }
                    )
            elif test["result"] == "acceptable":
                pass
            else:
                raise TestFailure(f"Unknown test result: {test['result']}")


# ---- Symmetric cipher handlers (non-AEAD) ----

_BLOCK_CIPHER_MAP = {
    "AES-CBC-PKCS5": ("AES", "/CBC/PKCS7", 1),
    "ARIA-CBC-PKCS5": ("ARIA", "/CBC/PKCS7", 1),
    "CAMELLIA-CBC-PKCS5": ("Camellia", "/CBC/PKCS7", 1),
    "AES-XTS": ("AES", "/XTS", 2),
}


@register("AES-CBC-PKCS5", "ARIA-CBC-PKCS5", "CAMELLIA-CBC-PKCS5", "AES-XTS")
def handle_block_cipher(data: dict, group: dict, test: dict) -> None:
    cipher_base, mode, key_divisor = _BLOCK_CIPHER_MAP[data["algorithm"]]
    key_size = group["keySize"] // key_divisor
    algo = f"{cipher_base}-{key_size}{mode}"

    key = _from_hex(test["key"])
    iv = _from_hex(test["iv"])

    msg = _from_hex(test["msg"])
    ct = _from_hex(test["ct"])

    def _fields(**extra):
        fields = {
            "Key": test["key"],
            "IV": test["iv"],
            "Msg": test["msg"],
            "CT": test["ct"],
        }
        fields.update(extra)
        return fields

    if test["result"] == "valid":
        try:
            enc = botan.SymmetricCipher(algo, True)
            enc.set_key(key)
            enc.start(iv)
            enc_out = enc.finish(msg)
        except botan.BotanException:
            # pylint: disable=raise-missing-from
            raise TestFailure(_fields(Note="Encryption failed"))
        if enc_out != ct:
            raise TestFailure(_fields(ComputedCT=enc_out.hex()))

        try:
            dec = botan.SymmetricCipher(algo, False)
            dec.set_key(key)
            dec.start(iv)
            dec_out = dec.finish(ct)
        except botan.BotanException:
            # pylint: disable=raise-missing-from
            raise TestFailure(_fields(Note="Decryption failed"))
        if dec_out != msg:
            raise TestFailure(_fields(DecryptedMsg=dec_out.hex()))

    elif test["result"] in ("invalid", "acceptable"):
        try:
            dec = botan.SymmetricCipher(algo, False)
            dec.set_key(key)
            dec.start(iv)
            dec_out = dec.finish(ct)
            if test["result"] == "invalid" and dec_out == msg:
                raise TestFailure(_fields(Note="Invalid test decrypted successfully"))
        except botan.BotanException:
            pass
    else:
        raise TestFailure(f"Unknown test result: {test['result']}")


# ---- Key wrap handlers ----

_KEYWRAP_CIPHERS = {
    "AES-WRAP": "AES-{keySize}",
    "AES-KWP": "AES-{keySize}",
    "ARIA-WRAP": "ARIA-{keySize}",
    "ARIA-KWP": "ARIA-{keySize}",
    "CAMELLIA-WRAP": "Camellia-{keySize}",
    "SEED-WRAP": "SEED",
}


def _keywrap_cipher(algorithm: str, key_size: int) -> str:
    template = _KEYWRAP_CIPHERS[algorithm]
    return template.format(keySize=key_size)


@register("AES-WRAP", "ARIA-WRAP", "CAMELLIA-WRAP", "SEED-WRAP")
def handle_keywrap(data: dict, group: dict, test: dict) -> None:
    cipher = _keywrap_cipher(data["algorithm"], group["keySize"])
    key = _from_hex(test["key"])
    msg = _from_hex(test["msg"])
    ct = _from_hex(test["ct"])

    if test["result"] == "valid":
        wrapped = botan.nist_key_wrap(key, msg, cipher)
        if wrapped != ct:
            raise TestFailure(
                {
                    "Key": test["key"],
                    "Msg": test["msg"],
                    "CT": test["ct"],
                    "ComputedCT": wrapped.hex(),
                }
            )
        try:
            unwrapped = botan.nist_key_unwrap(key, ct, cipher)
        except botan.BotanException:
            # pylint: disable=raise-missing-from
            raise TestFailure(
                {
                    "Key": test["key"],
                    "CT": test["ct"],
                    "Note": "Valid wrap unwrap failed",
                }
            )
        if unwrapped != msg:
            raise TestFailure(
                {
                    "Key": test["key"],
                    "CT": test["ct"],
                    "Msg": test["msg"],
                    "ComputedMsg": unwrapped.hex(),
                }
            )
    elif test["result"] == "invalid":
        try:
            unwrapped = botan.nist_key_unwrap(key, ct, cipher)
            if unwrapped == msg:
                raise TestFailure(
                    {
                        "Key": test["key"],
                        "CT": test["ct"],
                        "Note": "Invalid wrap unwrapped successfully",
                    }
                )
        except botan.BotanException:
            pass
    elif test["result"] == "acceptable":
        pass
    else:
        raise TestFailure(f"Unknown test result: {test['result']}")


@register("AES-KWP", "ARIA-KWP")
def handle_keywrap_padded(data: dict, group: dict, test: dict) -> None:
    cipher = _keywrap_cipher(data["algorithm"], group["keySize"])
    key = _from_hex(test["key"])
    msg = _from_hex(test["msg"])
    ct = _from_hex(test["ct"])

    if test["result"] == "valid":
        wrapped = botan.nist_key_wrap_padded(key, msg, cipher)
        if wrapped != ct:
            raise TestFailure(
                {
                    "Key": test["key"],
                    "Msg": test["msg"],
                    "CT": test["ct"],
                    "ComputedCT": wrapped.hex(),
                }
            )
        try:
            unwrapped = botan.nist_key_unwrap_padded(key, ct, cipher)
        except botan.BotanException:
            # pylint: disable=raise-missing-from
            raise TestFailure(
                {
                    "Key": test["key"],
                    "CT": test["ct"],
                    "Note": "Valid padded wrap unwrap failed",
                }
            )
        if unwrapped != msg:
            raise TestFailure(
                {
                    "Key": test["key"],
                    "CT": test["ct"],
                    "Msg": test["msg"],
                    "ComputedMsg": unwrapped.hex(),
                }
            )
    elif test["result"] == "invalid":
        try:
            unwrapped = botan.nist_key_unwrap_padded(key, ct, cipher)
            if unwrapped == msg:
                raise TestFailure(
                    {
                        "Key": test["key"],
                        "CT": test["ct"],
                        "Note": "Invalid padded wrap unwrapped successfully",
                    }
                )
        except botan.BotanException:
            pass
    elif test["result"] == "acceptable":
        pass
    else:
        raise TestFailure(f"Unknown test result: {test['result']}")


# ---- DSA handler ----


@register("DSA")
def handle_dsa(_data: dict, group: dict, test: dict) -> None:
    group_type = group["type"]
    if group_type == "DsaVerify":
        use_der = True
    elif group_type == "DsaP1363Verify":
        use_der = False
    else:
        raise TestFailure(f"Unknown DSA group type: {group_type}")

    try:
        pub_key = botan.PublicKey.load(_from_hex(group["publicKeyDer"]))
    except botan.BotanException:
        if test["result"] != "valid":
            return
        raise

    botan_hash = _map_hash(group["sha"])

    try:
        verifier = botan.PKVerify(pub_key, botan_hash, der=use_der)
        verifier.update(_from_hex(test["msg"]))
        valid = verifier.check_signature(_from_hex(test["sig"]))
    except botan.BotanException:
        if test["result"] != "valid":
            return
        raise

    expected_valid = test["result"] == "valid"
    if valid != expected_valid:
        raise TestFailure(
            {
                "Hash": group["sha"],
                "Msg": test["msg"],
                "Sig": test["sig"],
                "Expected": "valid" if expected_valid else "invalid",
                "Got": "valid" if valid else "invalid",
            }
        )


# ---- EdDSA handler ----


@register("EDDSA")
def handle_eddsa(_data: dict, group: dict, test: dict) -> None:
    try:
        pub_key = botan.PublicKey.load(_from_hex(group["publicKeyDer"]))
    except botan.BotanException:
        if test["result"] != "valid":
            return
        raise

    try:
        verifier = botan.PKVerify(pub_key, "Pure")
        verifier.update(_from_hex(test["msg"]))
        valid = verifier.check_signature(_from_hex(test["sig"]))
    except botan.BotanException:
        if test["result"] != "valid":
            return
        raise

    expected_valid = test["result"] == "valid"
    if valid != expected_valid:
        raise TestFailure(
            {
                "Curve": group["publicKey"]["curve"],
                "Msg": test["msg"],
                "Sig": test["sig"],
                "Expected": "valid" if expected_valid else "invalid",
                "Got": "valid" if valid else "invalid",
            }
        )


# ---- RSA signature handlers ----


def _map_hash(name: str) -> str:
    h = _HASH_NAME_MAP.get(name)
    if h is None:
        raise TestSkip(f"Hash {name} not supported")
    return h


def _rsa_pss_padding(group: dict) -> str:
    if group.get("mgf") != "MGF1":
        raise TestSkip(f"PSS with {group.get('mgf')} MGF not supported")
    sha = _map_hash(group["sha"])
    mgf_sha = _map_hash(group["mgfSha"])
    if sha != mgf_sha:
        raise TestSkip("PSS with different MGF hash not supported")
    s_len = group["sLen"]
    return f"PSSR({sha},MGF1,{s_len})"


def _rsa_pkcs1_padding(group: dict) -> str:
    return f"EMSA3({_map_hash(group['sha'])})"


def _rsa_verify(pub_key, padding: str, test: dict) -> None:
    try:
        verifier = botan.PKVerify(pub_key, padding)
        verifier.update(_from_hex(test["msg"]))
        valid = verifier.check_signature(_from_hex(test["sig"]))
    except botan.BotanException:
        if test["result"] != "valid":
            return
        raise

    expected_valid = test["result"] == "valid"
    if valid != expected_valid:
        raise TestFailure(
            {
                "Msg": test["msg"],
                "Sig": test["sig"],
                "Padding": padding,
                "Expected": "valid" if expected_valid else "invalid",
                "Got": "valid" if valid else "invalid",
            }
        )


@register("RSASSA-PKCS1-v1_5")
def handle_rsa_pkcs1_sig(_data: dict, group: dict, test: dict) -> None:
    group_type = group["type"]

    if group_type == "RsassaPkcs1Verify":
        try:
            pub_key = botan.PublicKey.load(_from_hex(group["publicKeyDer"]))
        except botan.BotanException:
            if test["result"] != "valid":
                return
            raise
        _rsa_verify(pub_key, _rsa_pkcs1_padding(group), test)

    elif group_type == "RsassaPkcs1Generate":
        try:
            priv_key = botan.PrivateKey.load(_from_hex(group["privateKeyPkcs8"]))
        except botan.BotanException:
            if test["result"] != "valid":
                return
            raise

        padding = _rsa_pkcs1_padding(group)
        try:
            signer = botan.PKSign(priv_key, padding)
            signer.update(_from_hex(test["msg"]))
            actual_sig = signer.finish(botan.RandomNumberGenerator("system"))
        except botan.BotanException:
            if test["result"] != "valid":
                return
            raise

        expected_sig = _from_hex(test["sig"])
        if actual_sig != expected_sig:
            raise TestFailure(
                {
                    "Msg": test["msg"],
                    "Padding": padding,
                    "Sig": test["sig"],
                    "ComputedSig": actual_sig.hex(),
                }
            )
    else:
        raise TestFailure(f"Unknown RSA PKCS1 sig group type: {group_type}")


@register("RSASSA-PSS")
def handle_rsa_pss_sig(_data: dict, group: dict, test: dict) -> None:
    group_type = group["type"]

    if group_type not in ("RsassaPssVerify", "RsassaPssWithParametersVerify"):
        raise TestFailure(f"Unknown RSA PSS group type: {group_type}")

    try:
        pub_key = botan.PublicKey.load(_from_hex(group["publicKeyDer"]))
    except botan.BotanException:
        if test["result"] != "valid":
            return
        raise

    _rsa_verify(pub_key, _rsa_pss_padding(group), test)


# ---- RSA encryption handlers ----


def _rsa_oaep_padding(group: dict) -> str:
    sha = _map_hash(group["sha"])
    mgf_sha = _map_hash(group["mgfSha"])
    return f"OAEP({sha},MGF1({mgf_sha}))"


@register("RSAES-OAEP")
def handle_rsa_oaep(_data: dict, group: dict, test: dict) -> None:
    if "otherPrimeInfos" in group.get("privateKey", {}):
        raise TestSkip("Multi-prime RSA not supported")

    # Botan's OAEP label parameter only accepts string labels, not arbitrary binary
    if test.get("label", "") != "":
        raise TestSkip("OAEP with binary label not supported in padding string parser")

    try:
        priv_key = botan.PrivateKey.load(_from_hex(group["privateKeyPkcs8"]))
    except botan.BotanException:
        if test["result"] != "valid":
            return
        raise

    padding = _rsa_oaep_padding(group)

    try:
        decryptor = botan.PKDecrypt(priv_key, padding)
        plaintext = decryptor.decrypt(_from_hex(test["ct"]))
    except botan.BotanException:
        if test["result"] != "valid":
            return
        raise

    expected = _from_hex(test["msg"])
    if test["result"] == "valid":
        if plaintext != expected:
            raise TestFailure(
                {
                    "Ctext": test["ct"],
                    "Ptext": test["msg"],
                    "Padding": padding,
                    "ComputedMsg": plaintext.hex(),
                }
            )
    elif test["result"] == "invalid":
        if plaintext == expected:
            raise TestFailure(
                {
                    "Ctext": test["ct"],
                    "Ptext": test["msg"],
                    "Padding": padding,
                    "Note": "Invalid test decrypted successfully",
                }
            )


@register("RSAES-PKCS1-v1_5")
def handle_rsa_pkcs1_enc(_data: dict, group: dict, test: dict) -> None:
    try:
        priv_key = botan.PrivateKey.load(_from_hex(group["privateKeyPkcs8"]))
    except botan.BotanException:
        if test["result"] != "valid":
            return
        raise

    try:
        decryptor = botan.PKDecrypt(priv_key, "PKCS1v15")
        plaintext = decryptor.decrypt(_from_hex(test["ct"]))
    except botan.BotanException:
        if test["result"] != "valid":
            return
        raise

    expected = _from_hex(test["msg"])
    if test["result"] == "valid":
        if plaintext != expected:
            raise TestFailure(
                {
                    "Ctext": test["ct"],
                    "Ptext": test["msg"],
                    "ComputedMsg": plaintext.hex(),
                }
            )
    elif test["result"] == "invalid":
        if plaintext == expected:
            raise TestFailure(
                {
                    "Ctext": test["ct"],
                    "Ptext": test["msg"],
                    "Note": "Invalid test decrypted successfully",
                }
            )


# ---- XDH handler (X25519, X448) ----

_XDH_LOAD_RAW = {
    "curve25519": botan.PrivateKey.load_x25519,
    "curve448": botan.PrivateKey.load_x448,
}


@register("XDH")
def handle_xdh(_data: dict, group: dict, test: dict) -> None:
    group_type = group.get("type", "")
    curve = group.get("curve", "")

    expected = _from_hex(test["shared"])

    # Load private key and public key bytes based on encoding format
    try:
        if group_type == "XdhComp":
            load_fn = _XDH_LOAD_RAW.get(curve)
            if load_fn is None:
                raise TestSkip(f"XDH curve {curve} not supported")
            priv_key = load_fn(_from_hex(test["private"]))
            pub_bytes = _from_hex(test["public"])
        elif group_type in ("XdhAsnComp", "XdhPemComp"):
            if group_type == "XdhAsnComp":
                priv_key = botan.PrivateKey.load(_from_hex(test["private"]))
                pub_key = botan.PublicKey.load(_from_hex(test["public"]))
            else:
                priv_key = botan.PrivateKey.load(test["private"].encode())
                pub_key = botan.PublicKey.load(test["public"].encode())
            pub_bytes = pub_key.to_raw()
        elif group_type == "XdhJwkComp":
            load_fn = _XDH_LOAD_RAW.get(curve)
            if load_fn is None:
                raise TestSkip(f"XDH curve {curve} not supported")
            # We extract raw bytes from the JWK, bypassing JWK structural
            # validation (kty, crv, missing fields). Skip InvalidPublic
            # tests since those test JWK parsing, not the crypto.
            if "InvalidPublic" in test.get("flags", []):
                raise TestSkip("JWK structural validation test")
            priv_key = load_fn(_b64url_decode(test["private"]["d"]))
            pub_bytes = _b64url_decode(test["public"]["x"])
        else:
            raise TestSkip(f"XDH group type {group_type!r} not supported")
    except (botan.BotanException, KeyError, ValueError):
        if test["result"] != "valid":
            return
        raise

    try:
        ka = botan.PKKeyAgreement(priv_key, "Raw")
        shared = ka.agree(pub_bytes, 0, b"")
    except botan.BotanException:
        if test["result"] != "valid":
            return
        raise

    if test["result"] not in ("valid", "acceptable"):
        raise TestFailure(
            {
                "Curve": curve,
                "Shared": shared.hex(),
                "Note": "Invalid test case produced a shared secret",
            }
        )

    if shared != expected:
        raise TestFailure(
            {
                "Curve": curve,
                "Shared": test["shared"],
                "ComputedShared": shared.hex(),
            }
        )


# ---- Primality test handler ----


@register("PrimalityTest")
def handle_primality(_data: dict, _group: dict, test: dict) -> None:
    value = test["value"]
    if value in ["", "00"]:
        return

    # This test encodes integers as signed twos complement for unclear reasons
    value_bytes = _from_hex(value)
    if value_bytes[0] & 0x80:
        is_prime = False
    else:
        n = botan.MPI(value, radix=16)
        rng = botan.RandomNumberGenerator("system")
        is_prime = n.is_prime(rng)

    expected_prime = test["result"] == "valid"

    if is_prime != expected_prime:
        raise TestFailure(
            {
                "Value": value,
                "Expected": "prime" if expected_prime else "composite",
                "Got": "prime" if is_prime else "composite",
            }
        )


# ---- Ignored algorithms ----

_registry.ignore(
    "AES-FF1",         # Not implemented
    "AES-GCM-SIV",     # Not implemented
    "A128CBC-HS256",   # Not implemented
    "A192CBC-HS384",   # Not implemented
    "A256CBC-HS512",   # Not implemented
    "AEGIS128",        # Not implemented
    "AEGIS128L",       # Not implemented
    "AEGIS256",        # Not implemented
    "ASCON128",        # Pre-NIST Ascon not implemented
    "ASCON128A",       # Pre-NIST Ascon not implemented
    "ASCON80PQ",       # Pre-NIST Ascon not implemented
    "BLS",             # Not implemented
    "PbeWithHmacSha1AndAes_128",  # PBES2 not directly exposed in API
    "PbeWithHmacSha1AndAes_192",
    "PbeWithHmacSha1AndAes_256",
    "PbeWithHmacSha224AndAes_128",
    "PbeWithHmacSha224AndAes_192",
    "PbeWithHmacSha224AndAes_256",
    "PbeWithHmacSha256AndAes_128",
    "PbeWithHmacSha256AndAes_192",
    "PbeWithHmacSha256AndAes_256",
    "PbeWithHmacSha384AndAes_128",
    "PbeWithHmacSha384AndAes_192",
    "PbeWithHmacSha384AndAes_256",
    "PbeWithHmacSha512AndAes_128",
    "PbeWithHmacSha512AndAes_192",
    "PbeWithHmacSha512AndAes_256",
    "EcCurveTest",     # Not even clear what this is for
    "MORUS640",        # Not implemented
    "MORUS1280",       # Not implemented
    "HMACSHA512/224",  # Not implemented
    "SipHashX-2-4",    # 128-bit SipHash variant, not implemented
    "SipHashX-4-8",    # 128-bit SipHash variant, not implemented
    "VMAC-AES",        # Not implemented
)


# ---- Entry point ----


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Wycheproof test vectors against Botan's Python bindings"
    )
    parser.add_argument(
        "wycheproof_dir",
        nargs="?",
        default=os.environ.get("WYCHEPROOF_DIR"),
        help="path to Wycheproof git checkout (default: $WYCHEPROOF_DIR)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="be noisy")
    parser.add_argument("--quiet", "-q", action="store_true", help="be quiet")
    parser.add_argument(
        "--jobs", "-j", type=int, default=None, help="number of workers"
    )
    parser.add_argument(
        "--filter",
        "-f",
        action="append",
        default=[],
        help="only run files matching FILTER (case-insensitive substring of filename or algorithm, may be repeated)",
    )
    args = parser.parse_args()

    if args.wycheproof_dir is None:
        parser.error(
            "wycheproof_dir argument or WYCHEPROOF_DIR environment variable required"
        )

    jobs = args.jobs
    if jobs is not None and jobs <= 0:
        parser.error("Invalid --jobs parameter")

    verbosity = 0 if args.quiet else (2 if args.verbose else 1)
    return run(args.wycheproof_dir, verbosity, jobs, args.filter or None)


if __name__ == "__main__":
    sys.exit(main())
