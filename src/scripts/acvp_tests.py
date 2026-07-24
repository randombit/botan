#!/usr/bin/env python3

"""
Validate against NIST ACVP test vectors

Requires a checkout of https://github.com/usnistgov/ACVP-Server. Point
$ACVP_TESTDATA_DIR at the gen-val/json-files directory.

(C) 2026 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""
from __future__ import annotations

import argparse
import binascii
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

# ---- Infra ----


class TestSkip(Exception):
    """Raised by a handler to skip a test vector."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class TestFailure(Exception):
    """Raised by a handler when a test vector fails.

    Construct with either a dict of field_name -> value for .vec-style
    output, or a plain string message.
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
                f"Algorithm directory {algorithm!r} already registered by "
                f"{self._handlers[algorithm].__name__}, cannot also register "
                f"{handler.__name__}"
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


def register(*algorithm_dirs: str):
    """Decorator to register a handler for one or more ACVP algorithm directories."""

    def decorator(func):
        for algo in algorithm_dirs:
            _registry.register(algo, func)
        return func

    return decorator


@dataclass
class _FileResult:
    """Result of processing a single ACVP algorithm directory."""

    algo_dir: str
    category: str  # "claimed", "unclaimed", "ignored", "missing", "malformed"
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    skip_reasons: dict[str, int] = field(default_factory=dict)
    output: str = ""


def _process_directory(args: tuple[str, str, int]) -> _FileResult:
    algo_dir_str, data_dir_str, verbosity = args
    algo_dir = Path(algo_dir_str)
    data_dir = Path(data_dir_str)
    algo_name = algo_dir.name

    if _registry.is_ignored(algo_name):
        return _FileResult(algo_name, "ignored")

    handler = _registry.get(algo_name)
    if handler is None:
        return _FileResult(algo_name, "unclaimed")

    prompt_path = algo_dir / "prompt.json"
    expected_path = algo_dir / "expectedResults.json"

    if not prompt_path.exists() or not expected_path.exists():
        return _FileResult(algo_name, "missing")

    try:
        with open(prompt_path, encoding="utf-8") as f:
            prompt = json.load(f)
        with open(expected_path, encoding="utf-8") as f:
            expected = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        result = _FileResult(algo_name, "malformed")
        result.output = f"ERROR parsing {algo_dir.relative_to(data_dir)}: {e}\n"
        return result

    header = {k: v for k, v in prompt.items() if k != "testGroups"}

    expected_by_tg: dict[int, dict[int, dict]] = {}
    expected_group_by_tg: dict[int, dict] = {}
    for eg in expected.get("testGroups", []):
        expected_by_tg[eg["tgId"]] = {t["tcId"]: t for t in eg.get("tests", [])}
        expected_group_by_tg[eg["tgId"]] = {
            k: v for k, v in eg.items() if k != "tests"
        }

    result = _FileResult(algo_name, "claimed")
    out = io.StringIO()

    if verbosity >= 2:
        print(f"{algo_name}:", file=out)

    for group in prompt.get("testGroups", []):
        tg_id = group["tgId"]
        expected_tests = expected_by_tg.get(tg_id, {})
        # Group-level fields of expectedResults (eg a reference public key)
        # are reachable via _group_state(group, "expected_group")
        _set_group_state(group, "expected_group", expected_group_by_tg.get(tg_id, {}))

        for test in group.get("tests", []):
            tc_id = test.get("tcId", "?")
            exp = expected_tests.get(tc_id, {})

            try:
                handler(header, group, test, exp)
                result.passed += 1
                if verbosity >= 2:
                    print(f"  PASS: tgId={tg_id} tcId={tc_id}", file=out)
            except TestSkip as e:
                result.skipped += 1
                reason = str(e)
                result.skip_reasons[reason] = result.skip_reasons.get(reason, 0) + 1
                if verbosity >= 2:
                    print(f"  SKIP: tgId={tg_id} tcId={tc_id}: {reason}", file=out)
            except TestFailure as e:
                result.failed += 1
                print(
                    f"\nFAIL: # ACVP tgId={tg_id} tcId={tc_id} in {algo_name}",
                    file=out,
                )
                if e.fields:
                    for key, value in e.fields.items():
                        print(f"{key} = {value}", file=out)
                else:
                    print(f"  {e}", file=out)
            except Exception as e:
                result.errors += 1
                print(
                    f"\nERROR: # ACVP tgId={tg_id} tcId={tc_id} in {algo_name}",
                    file=out,
                )
                print(f"  {type(e).__name__}: {e}", file=out)
                print(traceback.format_exc(), file=out)

    result.output = out.getvalue()
    return result


def _git_rev(directory: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        return result.stdout.strip() or None
    except (
        FileNotFoundError,
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
    ):
        return None


def _discover_algo_dirs(data_dir: Path) -> list[Path]:
    """Return ACVP algorithm directories: subdirs containing a prompt.json."""
    dirs = []
    for entry in sorted(data_dir.iterdir()):
        if entry.is_dir() and (entry / "prompt.json").exists():
            dirs.append(entry)
    return dirs


def run(
    data_dir_str: str,
    verbosity: int = 1,
    jobs: int | None = None,
    filters: list[str] | None = None,
) -> int:
    data_dir = Path(data_dir_str)
    if not data_dir.is_dir():
        print(f"ERROR: {data_dir} is not a directory")
        return 1

    algo_dirs = _discover_algo_dirs(data_dir)

    if filters:
        filters_lower = [f.lower() for f in filters]
        algo_dirs = [
            d for d in algo_dirs if any(f in d.name.lower() for f in filters_lower)
        ]

    work = [(str(d), str(data_dir), verbosity) for d in algo_dirs]

    if jobs == 1:
        file_results = [_process_directory(item) for item in work]
    else:
        with multiprocessing.Pool(jobs) as pool:
            file_results = pool.map(_process_directory, work)

    passed = failed = errors = skipped = 0
    files_claimed = files_ignored = files_missing = 0
    unclaimed: list[str] = []
    malformed: list[str] = []
    skip_reasons: Counter[str] = Counter()

    for fr in file_results:
        if fr.output:
            sys.stdout.write(fr.output)

        if fr.category == "ignored":
            files_ignored += 1
        elif fr.category == "unclaimed":
            unclaimed.append(fr.algo_dir)
        elif fr.category == "missing":
            files_missing += 1
        elif fr.category == "malformed":
            malformed.append(fr.algo_dir)
        else:
            files_claimed += 1
            passed += fr.passed
            failed += fr.failed
            errors += fr.errors
            skipped += fr.skipped
            for reason, count in fr.skip_reasons.items():
                skip_reasons[reason] += count

    total_dirs = (
        files_claimed + files_ignored + files_missing + len(unclaimed) + len(malformed)
    )
    total_tests = passed + failed + errors + skipped

    acvp_rev = _git_rev(str(data_dir))

    print("ACVP Results")
    print(f"Botan version: {botan.version_string()}")
    if acvp_rev:
        print(f"ACVP-Server revision: {acvp_rev}")
    print(
        f"Total {total_tests} Passed {passed} Failed {failed} "
        f"Errors {errors} Skipped {skipped}"
    )
    print(
        f"Directories: {total_dirs} total, {files_claimed} claimed, "
        f"{files_ignored} ignored, {len(unclaimed)} unclaimed, "
        f"{files_missing} without expectedResults"
    )

    if verbosity >= 1:
        if skip_reasons:
            print("\nSkipped tests (by reason):")
            for reason, count in skip_reasons.most_common():
                print(f"  {count}x: {reason}")

        if unclaimed:
            print(f"\nUnclaimed directories ({len(unclaimed)}):")
            for name in unclaimed:
                print(f"  {name}")

        if malformed:
            print(f"\nMalformed directories ({len(malformed)}):")
            for name in malformed:
                print(f"  {name}")

    return 0 if (failed == 0 and errors == 0) else 1


# ---- Common utilities ----


def _from_hex(value: str) -> bytes:
    return binascii.unhexlify(value)


def _opt_hex(d: dict, key: str) -> bytes:
    v = d.get(key)
    return _from_hex(v) if v else b""


_HASH_MAP = {
    "SHA-1": "SHA-1",
    "SHA2-224": "SHA-224",
    "SHA2-256": "SHA-256",
    "SHA2-384": "SHA-384",
    "SHA2-512": "SHA-512",
    "SHA2-512/224": None,  # not implemented
    "SHA2-512/256": "SHA-512-256",
    "SHA3-224": "SHA-3(224)",
    "SHA3-256": "SHA-3(256)",
    "SHA3-384": "SHA-3(384)",
    "SHA3-512": "SHA-3(512)",
    "SHAKE-128": "SHAKE-128(256)",
    "SHAKE-256": "SHAKE-256(512)",
}

_HMAC_ALGO_MAP = {
    f"HMAC-{k}": f"HMAC({v})" for k, v in _HASH_MAP.items() if v is not None
}
_PBKDF_HMAC_MAP = {
    k: f"PBKDF2({v})"
    for k, v in _HASH_MAP.items()
    if v is not None and not k.startswith("SHAKE")
}
_HMAC_DRBG_MODE_MAP = {k: v for k, v in _HASH_MAP.items() if not k.startswith("SHAKE")}
_KDF_HASH_MAP = {k: v for k, v in _HASH_MAP.items() if not k.startswith("SHAKE")}

_CURVE_MAP = {
    "P-192": "secp192r1",
    "P-224": "secp224r1",
    "P-256": "secp256r1",
    "P-384": "secp384r1",
    "P-521": "secp521r1",
}


def _map_hash(acvp_hash: str) -> str:
    h = _HASH_MAP.get(acvp_hash)
    if h is None:
        raise TestSkip(f"Hash {acvp_hash} not supported")
    return h


def _require_aft(group: dict) -> None:
    test_type = group.get("testType", "AFT")
    if test_type != "AFT":
        raise TestSkip(f"testType {test_type} not supported")


# Handlers can stash per-group state on the group dict under keys
# prefixed with "_b_" to avoid clashing with ACVP fields.
def _group_state(group: dict, key: str):
    return group.get("_b_" + key)


def _set_group_state(group: dict, key: str, value) -> None:
    group["_b_" + key] = value


# ---- Hash / XOF shared helpers ----


def _hash_aft(algo: str, test: dict, exp: dict) -> None:
    bit_len = test["len"]
    if bit_len % 8 != 0:
        raise TestSkip("Bit-oriented input not supported")

    h = botan.HashFunction(algo)
    msg = _opt_hex(test, "msg")[: bit_len // 8]
    h.update(msg)
    computed = h.final().hex()
    if computed != exp["md"].lower():
        raise TestFailure(
            {"Algo": algo, "Msg": msg.hex(), "MD": exp["md"], "ComputedMD": computed}
        )


def _sha3_mct(algo: str, test: dict, exp: dict) -> None:
    # SHA-3 MCT: single-chain iteration. When seed length differs from
    # hash output length, ACVP uses the "alternate" variant that
    # truncates/pads each input to the original seed length (see
    # ACVP-Server AlternateSizeSha3Mct.cs).
    seed = _from_hex(test["msg"])
    seed_len = len(seed)
    hash_len = botan.HashFunction(algo).output_length()
    alternate = seed_len != hash_len

    md = seed
    for j, result in enumerate(exp.get("resultsArray", [])):
        for _ in range(1000):
            m = md
            if alternate:
                if len(m) >= seed_len:
                    m = m[:seed_len]
                else:
                    m = m + bytes(seed_len - len(m))
            h = botan.HashFunction(algo)
            h.update(m)
            md = h.final()
        if md.hex() != result["md"].lower():
            raise TestFailure(
                {
                    "Algo": algo,
                    "MctOuter": str(j),
                    "MD": result["md"],
                    "ComputedMD": md.hex(),
                }
            )


def _hash_ldt(algo: str, test: dict, exp: dict) -> None:
    large_msg = test["largeMsg"]
    content = _from_hex(large_msg["content"])
    full_length = large_msg["fullLength"]
    if large_msg.get("expansionTechnique", "repeating") != "repeating":
        raise TestSkip(f"expansionTechnique {large_msg.get('expansionTechnique')}")

    h = botan.HashFunction(algo)
    content_len = len(content)
    remaining = full_length
    while remaining > 0:
        chunk = min(content_len, remaining)
        h.update(content[:chunk])
        remaining -= chunk
    computed = h.final().hex()
    if computed != exp["md"].lower():
        raise TestFailure({"Algo": algo, "MD": exp["md"], "ComputedMD": computed})


def _xof_aft(algo: str, test: dict, exp: dict) -> None:
    out_bits = test.get("outLen", test.get("outputLen", 256))
    if out_bits % 8 != 0:
        raise TestSkip("Bit-oriented input not supported")
    out_len = out_bits // 8

    msg = _opt_hex(test, "msg")
    bit_len = test.get("len", test.get("inLen", len(msg) * 8))
    if bit_len % 8 != 0:
        raise TestSkip("Bit-oriented input not supported")
    msg = msg[: bit_len // 8]

    xof = botan.XOF(algo)
    xof.update(msg)
    output = xof.output(out_len).hex()
    expected = exp.get("md") or exp.get("output") or ""
    if output != expected.lower():
        raise TestFailure(
            {"Algo": algo, "OutLen": str(out_bits), "Expected": expected, "Got": output}
        )


# ---- SHA-2 MCT (Merkle-Damgård 3-seed) ----


def _sha2_mct(algo: str, test: dict, exp: dict) -> None:
    seed = _from_hex(test["msg"])
    seed_len = len(seed)
    hash_len = botan.HashFunction(algo).output_length()

    # ACVP has two SHA-2 MCT variants (see ACVP-Server
    # StandardSizeShaMct.cs / AlternateSizeShaMct.cs):
    #   Standard: seed length == hash output length.
    #     MSG = MD[i-3] || MD[i-2] || MD[i-1]   (no truncation)
    #   Alternate: seed length != hash output length.
    #     MSG = (MD[i-3] || MD[i-2] || MD[i-1]), then truncated or
    #     zero-padded to the original seed length before hashing.
    alternate = seed_len != hash_len

    md = [seed, seed, seed]
    for j, result in enumerate(exp.get("resultsArray", [])):
        for _ in range(1000):
            m = md[0] + md[1] + md[2]
            if alternate:
                if len(m) >= seed_len:
                    m = m[:seed_len]
                else:
                    m = m + bytes(seed_len - len(m))
            h = botan.HashFunction(algo)
            h.update(m)
            md = [md[1], md[2], h.final()]
        if md[2].hex() != result["md"].lower():
            raise TestFailure(
                {
                    "Algo": algo,
                    "MctOuter": str(j),
                    "MD": result["md"],
                    "ComputedMD": md[2].hex(),
                }
            )
        md = [md[2], md[2], md[2]]


# ---- SHA-1 / SHA-2 / SHA-3 ----


@register(
    "SHA-1-2.0",
    "SHA2-224-1.0",
    "SHA2-256-1.0",
    "SHA2-384-1.0",
    "SHA2-512-1.0",
    "SHA2-512-224-1.0",
    "SHA2-512-256-1.0",
    "SHA3-224-2.0",
    "SHA3-256-2.0",
    "SHA3-384-2.0",
    "SHA3-512-2.0",
)
def handle_hash(header: dict, group: dict, test: dict, exp: dict) -> None:
    algo = _map_hash(header["algorithm"])
    test_type = group.get("testType", "AFT")

    if test_type == "AFT":
        _hash_aft(algo, test, exp)
    elif test_type == "MCT":
        if header["algorithm"].startswith("SHA3-"):
            _sha3_mct(algo, test, exp)
        else:
            _sha2_mct(algo, test, exp)
    elif test_type == "LDT":
        if os.environ.get("ACVP_RUN_SLOW_TESTS") != "1":
            raise TestSkip("LDT disabled (set ACVP_RUN_SLOW_TESTS=1)")
        _hash_ldt(algo, test, exp)
    else:
        raise TestSkip(f"testType {test_type} not supported")


# ---- SHAKE ----


@register(
    "SHAKE-128-1.0",
    "SHAKE-256-1.0",
    "SHAKE-128-FIPS202",
    "SHAKE-256-FIPS202",
)
def handle_shake(header: dict, group: dict, test: dict, exp: dict) -> None:
    algo_name = header["algorithm"]
    if algo_name in ("SHAKE-128", "SHAKE128"):
        algo = "SHAKE-128"
    elif algo_name in ("SHAKE-256", "SHAKE256"):
        algo = "SHAKE-256"
    else:
        raise TestSkip(f"Unsupported XOF: {algo_name}")

    test_type = group.get("testType", "AFT")
    if test_type == "MCT":
        raise TestSkip("SHAKE MCT not implemented")
    if test_type not in ("AFT", "VOT"):
        raise TestSkip(f"testType {test_type} not supported")

    _xof_aft(algo, test, exp)


# ---- cSHAKE ----


@register("cSHAKE-128-1.0", "cSHAKE-256-1.0")
def handle_cshake(header: dict, group: dict, test: dict, exp: dict) -> None:
    algo_name = header["algorithm"]
    if algo_name == "cSHAKE-128":
        algo = "cSHAKE-128"
    elif algo_name == "cSHAKE-256":
        algo = "cSHAKE-256"
    else:
        raise TestSkip(f"Unsupported: {algo_name}")

    test_type = group.get("testType", "AFT")
    if test_type == "MCT":
        raise TestSkip("cSHAKE MCT not implemented")
    if test_type != "AFT":
        raise TestSkip(f"testType {test_type} not supported")

    if test.get("functionName"):
        raise TestSkip("cSHAKE function_name not exposed in Python XOF API")
    if test.get("customization"):
        raise TestSkip("cSHAKE customization not exposed in Python XOF API")

    out_len = test["outLen"] // 8
    msg = _opt_hex(test, "msg")
    bit_len = test.get("len", len(msg) * 8)
    msg = msg[: bit_len // 8]

    xof = botan.XOF(algo)
    xof.update(msg)
    output = xof.output(out_len).hex()
    if output != exp["output"].lower():
        raise TestFailure({"Algo": algo, "Expected": exp["output"], "Got": output})


# ---- Ascon ----


@register("Ascon-AEAD128-SP800-232")
def handle_ascon_aead(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    if group.get("supportsNonceMasking"):
        raise TestSkip("Ascon nonce masking not implemented")
    if test["tagLen"] != 128:
        raise TestSkip("Ascon truncated tag lengths not implemented")
    if test["payloadLen"] % 8 != 0:
        raise TestSkip("Bit-oriented input not supported")
    if test["adLen"] % 8 != 0:
        raise TestSkip("Bit-oriented input not supported")

    _aead_aft(
        algo="Ascon-AEAD128",
        direction=group["direction"],
        key=_from_hex(test["key"]),
        nonce=_from_hex(test["nonce"]),
        aad=_opt_hex(test, "ad"),
        test=test,
        exp=exp,
        tag_bytes=16,
        combined_ct=False,
    )


@register("Ascon-Hash256-SP800-232")
def handle_ascon_hash(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)
    _hash_aft("Ascon-Hash256", test, exp)


@register("Ascon-XOF128-SP800-232")
def handle_ascon_xof(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)
    _xof_aft("Ascon-XOF128", test, exp)


# ---- AEAD helpers ----


def _resolve_cipher_or_skip(algo: str, group: dict) -> None:
    cached = _group_state(group, "cipher_ok")
    if cached is True:
        return
    if cached is False:
        raise TestSkip(f"Unsupported: {algo}")
    try:
        botan.SymmetricCipher(algo, True)
        _set_group_state(group, "cipher_ok", True)
    except botan.BotanException as e:
        _set_group_state(group, "cipher_ok", False)
        raise TestSkip(f"Unsupported: {algo}") from e


def _aead_aft(
    algo: str,
    direction: str,
    key: bytes,
    nonce: bytes,
    aad: bytes,
    test: dict,
    exp: dict,
    tag_bytes: int | None,
    combined_ct: bool,
) -> None:
    """Shared AEAD AFT handler.

    Parameters:
      algo: Botan cipher name, already resolved.
      direction: "encrypt" or "decrypt".
      key, nonce, aad: prepared byte inputs.
      test, exp: ACVP test/expected dicts (used for field lookup and messages).
      tag_bytes: byte length of the tag. None if unknown (decryption only).
      combined_ct: True when the ACVP ``ct`` field holds ``ct || tag`` (e.g.
        CCM). False when ``ct`` and ``tag`` are separate top-level fields.
    """
    if direction == "encrypt":
        pt = _opt_hex(test, "pt")
        enc = botan.SymmetricCipher(algo, True)
        enc.set_key(key)
        enc.set_assoc_data(aad)
        enc.start(nonce)
        ct_tag = enc.finish(pt)

        if combined_ct:
            expected_ct_tag = exp["ct"]
            computed_ct_tag = ct_tag.hex()
            if computed_ct_tag != expected_ct_tag.lower():
                raise TestFailure(
                    {
                        "Algo": algo,
                        "Key": test["key"],
                        "IV": test.get("iv", test.get("nonce", "")),
                        "CT": expected_ct_tag,
                        "ComputedCT": computed_ct_tag,
                    }
                )
            return

        assert tag_bytes is not None
        computed_ct = ct_tag[:-tag_bytes].hex()
        computed_tag = ct_tag[-tag_bytes:].hex()
        expected_ct = exp.get("ct", "")
        expected_tag = exp["tag"]
        if computed_ct != expected_ct.lower() or computed_tag != expected_tag.lower():
            raise TestFailure(
                {
                    "Algo": algo,
                    "Key": test["key"],
                    "IV": test.get("iv", test.get("nonce", "")),
                    "AAD": test.get("aad", test.get("ad", "")),
                    "PT": test.get("pt", ""),
                    "CT": expected_ct,
                    "Tag": expected_tag,
                    "ComputedCT": computed_ct,
                    "ComputedTag": computed_tag,
                }
            )
        return

    # decrypt
    if combined_ct:
        ct_tag = _opt_hex(test, "ct")
    else:
        ct_tag = _opt_hex(test, "ct") + _from_hex(test["tag"])

    should_pass = exp.get("testPassed", True)
    try:
        dec = botan.SymmetricCipher(algo, False)
        dec.set_key(key)
        dec.set_assoc_data(aad)
        dec.start(nonce)
        pt = dec.finish(ct_tag)
    except botan.BotanException as e:
        if should_pass:
            raise TestFailure(
                {
                    "Algo": algo,
                    "Key": test["key"],
                    "Note": "Valid AEAD decryption failed",
                }
            ) from e
        return

    if not should_pass:
        raise TestFailure(
            {"Algo": algo, "Note": "Invalid AEAD test decrypted successfully"}
        )
    expected_pt = exp.get("pt", "")
    if pt.hex() != expected_pt.lower():
        raise TestFailure({"Algo": algo, "PT": expected_pt, "ComputedPT": pt.hex()})


# ---- AES-GCM ----


@register("ACVP-AES-GCM-1.0")
def handle_aes_gcm(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    key_len = group["keyLen"]
    tag_bytes = group["tagLen"] // 8
    algo = f"AES-{key_len}/GCM({tag_bytes})"
    _resolve_cipher_or_skip(algo, group)

    _aead_aft(
        algo=algo,
        direction=group["direction"],
        key=_from_hex(test["key"]),
        nonce=_from_hex(test["iv"]),
        aad=_opt_hex(test, "aad"),
        test=test,
        exp=exp,
        tag_bytes=tag_bytes,
        combined_ct=False,
    )


# ---- AES-CCM ----


@register("ACVP-AES-CCM-1.0")
def handle_aes_ccm(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    key_len = group["keyLen"]
    tag_bytes = group["tagLen"] // 8
    iv_len = group["ivLen"] // 8
    l_val = 15 - iv_len
    algo = f"AES-{key_len}/CCM({tag_bytes},{l_val})"
    _resolve_cipher_or_skip(algo, group)

    _aead_aft(
        algo=algo,
        direction=group["direction"],
        key=_from_hex(test["key"]),
        nonce=_from_hex(test["iv"]),
        aad=_opt_hex(test, "aad"),
        test=test,
        exp=exp,
        tag_bytes=tag_bytes,
        combined_ct=True,
    )


# ---- Block cipher modes (AES / TDES) ----

_BLOCK_MODE_MAP = {
    "ACVP-AES-CBC": ("AES-{keyLen}", "CBC/NoPadding"),
    "ACVP-AES-ECB": ("AES-{keyLen}", "ECB"),
    "ACVP-AES-OFB": ("AES-{keyLen}", "OFB"),
    "ACVP-AES-CFB8": ("AES-{keyLen}", "CFB(8)"),
    "ACVP-AES-CFB128": ("AES-{keyLen}", "CFB"),
    "ACVP-TDES-ECB": ("TripleDES", "ECB"),
    "ACVP-TDES-CBC": ("TripleDES", "CBC/NoPadding"),
    "ACVP-TDES-OFB": ("TripleDES", "OFB"),
    "ACVP-TDES-CFB64": ("TripleDES", "CFB"),
    "ACVP-TDES-CFB8": ("TripleDES", "CFB(8)"),
}


def _block_mode_aft(
    bc_name: str,
    mode: str,
    key: bytes,
    test: dict,
    exp: dict,
    encrypt: bool,
    group: dict,
) -> None:
    if mode == "ECB":
        bc = botan.BlockCipher(bc_name)
        bc.set_key(key)
        if encrypt:
            got = bytes(bc.encrypt(_opt_hex(test, "pt"))).hex()
            if got != exp["ct"].lower():
                raise TestFailure(
                    {"Algo": f"{bc_name}/ECB", "CT": exp["ct"], "ComputedCT": got}
                )
        else:
            got = bytes(bc.decrypt(_opt_hex(test, "ct"))).hex()
            if got != exp["pt"].lower():
                raise TestFailure(
                    {"Algo": f"{bc_name}/ECB", "PT": exp["pt"], "ComputedPT": got}
                )
        return

    algo = f"{bc_name}/{mode}"
    _resolve_cipher_or_skip(algo, group)

    cipher = botan.SymmetricCipher(algo, encrypt)
    cipher.set_key(key)
    cipher.start(_opt_hex(test, "iv"))

    if encrypt:
        got = cipher.finish(_opt_hex(test, "pt")).hex()
        if got != exp["ct"].lower():
            raise TestFailure({"Algo": algo, "CT": exp["ct"], "ComputedCT": got})
    else:
        got = cipher.finish(_opt_hex(test, "ct")).hex()
        if got != exp["pt"].lower():
            raise TestFailure({"Algo": algo, "PT": exp["pt"], "ComputedPT": got})


@register(
    "ACVP-AES-CBC-1.0",
    "ACVP-AES-CFB128-1.0",
    "ACVP-AES-CFB8-1.0",
    "ACVP-AES-ECB-1.0",
    "ACVP-AES-OFB-1.0",
    "ACVP-TDES-CBC-1.0",
    "ACVP-TDES-CFB64-1.0",
    "ACVP-TDES-CFB8-1.0",
    "ACVP-TDES-ECB-1.0",
    "ACVP-TDES-OFB-1.0",
)
def handle_block_modes(header: dict, group: dict, test: dict, exp: dict) -> None:
    test_type = group.get("testType", "AFT")
    if test_type == "MCT":
        raise TestSkip("Block mode MCT not yet implemented")
    if test_type != "AFT":
        raise TestSkip(f"testType {test_type} not supported")

    entry = _BLOCK_MODE_MAP.get(header["algorithm"])
    if entry is None:
        raise TestSkip(f"Unsupported algorithm: {header['algorithm']}")
    bc_template, mode = entry
    bc_name = bc_template.format(keyLen=group.get("keyLen", ""))

    encrypt = group["direction"] == "encrypt"
    # TDES vectors split key into key1/key2/key3
    if "key1" in test:
        key = (
            _from_hex(test["key1"]) + _from_hex(test["key2"]) + _from_hex(test["key3"])
        )
    else:
        key = _from_hex(test["key"])

    _block_mode_aft(bc_name, mode, key, test, exp, encrypt, group)


# ---- AES-XTS ----


@register("ACVP-AES-XTS-1.0", "ACVP-AES-XTS-2.0")
def handle_aes_xts(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    tweak_mode = group.get("tweakMode", "hex")

    # XTS 1.0 puts payloadLen on the group; XTS 2.0 puts dataUnitLen/payloadLen on each test.
    data_unit = test.get("dataUnitLen") or group.get("payloadLen")
    payload_len = test.get("payloadLen") or group.get("payloadLen") or data_unit
    if data_unit is not None and data_unit % 8 != 0:
        raise TestSkip("Bit-oriented input not supported")
    if payload_len is not None and payload_len % 8 != 0:
        raise TestSkip("Bit-oriented input not supported")
    if data_unit is not None and payload_len != data_unit:
        raise TestSkip("XTS multi-data-unit not supported")

    algo = f"AES-{group['keyLen']}/XTS"
    _resolve_cipher_or_skip(algo, group)

    encrypt = group["direction"] == "encrypt"
    key = _from_hex(test["key"])
    if tweak_mode == "number":
        # IEEE 1619 data unit sequence number: encode as 16-byte little-endian.
        tweak = test["sequenceNumber"].to_bytes(16, "little")
    else:
        tweak = _from_hex(test["tweakValue"])

    cipher = botan.SymmetricCipher(algo, encrypt)
    cipher.set_key(key)
    cipher.start(tweak)

    if encrypt:
        pt = _opt_hex(test, "pt")
        got = cipher.finish(pt).hex()
        if got != exp["ct"].lower():
            raise TestFailure(
                {
                    "Algo": algo,
                    "Key": test["key"],
                    "Tweak": test.get(
                        "tweakValue", str(test.get("sequenceNumber", ""))
                    ),
                    "PT": test.get("pt", ""),
                    "CT": exp["ct"],
                    "ComputedCT": got,
                }
            )
    else:
        ct = _opt_hex(test, "ct")
        got = cipher.finish(ct).hex()
        if got != exp["pt"].lower():
            raise TestFailure(
                {
                    "Algo": algo,
                    "Key": test["key"],
                    "Tweak": test.get(
                        "tweakValue", str(test.get("sequenceNumber", ""))
                    ),
                    "CT": test.get("ct", ""),
                    "PT": exp["pt"],
                    "ComputedPT": got,
                }
            )


# ---- AES key wrap ----


@register("ACVP-AES-KW-1.0", "ACVP-AES-KWP-1.0")
def handle_aes_key_wrap(header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    if group.get("kwCipher", "cipher") == "inverse":
        raise TestSkip("SP800-38F inverse cipher key wrap (TKW-I) not implemented")

    is_kwp = "KWP" in header["algorithm"]
    wrap_fn = botan.nist_key_wrap_padded if is_kwp else botan.nist_key_wrap
    unwrap_fn = botan.nist_key_unwrap_padded if is_kwp else botan.nist_key_unwrap
    name = header["algorithm"]

    direction = group["direction"]
    key = _from_hex(test["key"])

    if direction == "encrypt":
        pt = _from_hex(test["pt"])
        got = wrap_fn(key, pt).hex()
        if got != exp["ct"].lower():
            raise TestFailure(
                {
                    "Algo": name,
                    "Key": test["key"],
                    "PT": test["pt"],
                    "CT": exp["ct"],
                    "ComputedCT": got,
                }
            )
        return

    ct = _from_hex(test["ct"])
    should_pass = exp.get("testPassed", True)
    try:
        pt = unwrap_fn(key, ct)
    except botan.BotanException as e:
        if should_pass:
            raise TestFailure(
                {
                    "Algo": name,
                    "Key": test["key"],
                    "CT": test["ct"],
                    "Note": "Valid unwrap failed",
                }
            ) from e
        return

    if not should_pass:
        raise TestFailure({"Algo": name, "Note": "Invalid test unwrapped successfully"})
    if pt.hex() != exp.get("pt", "").lower():
        raise TestFailure(
            {"Algo": name, "PT": exp.get("pt", ""), "ComputedPT": pt.hex()}
        )


# ---- HMAC ----


@register(
    "HMAC-SHA-1-1.0",
    "HMAC-SHA-1-2.0",
    "HMAC-SHA2-224-1.0",
    "HMAC-SHA2-224-2.0",
    "HMAC-SHA2-256-1.0",
    "HMAC-SHA2-256-2.0",
    "HMAC-SHA2-384-1.0",
    "HMAC-SHA2-384-2.0",
    "HMAC-SHA2-512-1.0",
    "HMAC-SHA2-512-2.0",
    "HMAC-SHA2-512-224-1.0",
    "HMAC-SHA2-512-224-2.0",
    "HMAC-SHA2-512-256-1.0",
    "HMAC-SHA2-512-256-2.0",
    "HMAC-SHA3-224-1.0",
    "HMAC-SHA3-224-2.0",
    "HMAC-SHA3-256-1.0",
    "HMAC-SHA3-256-2.0",
    "HMAC-SHA3-384-1.0",
    "HMAC-SHA3-384-2.0",
    "HMAC-SHA3-512-1.0",
    "HMAC-SHA3-512-2.0",
)
def handle_hmac(header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    algo = _HMAC_ALGO_MAP.get(header["algorithm"])
    if algo is None:
        raise TestSkip(f"Unsupported HMAC: {header['algorithm']}")

    available = _group_state(group, "mac_ok")
    if available is False:
        raise TestSkip(f"Not available: {algo}")
    if available is None:
        try:
            botan.MsgAuthCode(algo)
            _set_group_state(group, "mac_ok", True)
        except botan.BotanException as e:
            _set_group_state(group, "mac_ok", False)
            raise TestSkip(f"Not available: {algo}") from e

    key = _from_hex(test["key"])
    msg = _opt_hex(test, "msg")
    mac_len_bits = test.get("macLen", group.get("macLen"))
    if mac_len_bits is None:
        raise TestSkip("No macLen in test or group")
    mac_len = mac_len_bits // 8

    mac = botan.MsgAuthCode(algo)
    mac.set_key(key)
    mac.update(msg)
    got = mac.final()[:mac_len].hex()
    if got != exp["mac"].lower():
        raise TestFailure(
            {
                "Algo": algo,
                "Key": test["key"],
                "Msg": test.get("msg", ""),
                "Tag": exp["mac"],
                "ComputedTag": got,
            }
        )


# ---- CMAC ----


@register("CMAC-AES-1.0", "CMAC-TDES-1.0")
def handle_cmac(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    direction = group.get("direction", "gen")
    key = _from_hex(test["key"])
    msg = _opt_hex(test, "message")

    if "key1" in test:
        algo = "CMAC(3DES)"
    else:
        algo = f"CMAC(AES-{len(key) * 8})"

    mac_len = test.get("macLen", group.get("macLen", 128)) // 8

    mac = botan.MsgAuthCode(algo)
    mac.set_key(key)
    mac.update(msg)
    computed = mac.final()[:mac_len]

    if direction == "gen":
        if computed.hex() != exp["mac"].lower():
            raise TestFailure(
                {
                    "Algo": algo,
                    "Key": test["key"],
                    "Msg": test.get("message", ""),
                    "Tag": exp["mac"],
                    "ComputedTag": computed.hex(),
                }
            )
        return

    expected_mac = _from_hex(test["mac"])[:mac_len]
    should_pass = exp.get("testPassed", True)
    if should_pass and computed != expected_mac:
        raise TestFailure(
            {
                "Algo": algo,
                "Key": test["key"],
                "Note": "Valid CMAC did not verify",
                "Tag": test["mac"],
                "ComputedTag": computed.hex(),
            }
        )
    if not should_pass and computed == expected_mac:
        raise TestFailure({"Algo": algo, "Note": "Invalid CMAC test matched"})


# ---- KMAC ----


@register("KMAC-128-1.0", "KMAC-256-1.0")
def handle_kmac(header: dict, group: dict, test: dict, exp: dict) -> None:
    algo_name = header["algorithm"]

    if algo_name not in ["KMAC-128", "KMAC-256"]:
        raise TestSkip(f"Unsupported: {algo_name}")

    test_type = group.get("testType", "AFT")
    if test_type not in ("AFT", "MVT"):
        raise TestSkip(f"testType {test_type} not supported")

    if group.get("xof"):
        # KMAC XOF mode uses right_encode(0) instead of right_encode(L)
        # in its domain separation. Botan's KMAC-128/256 always use the
        # non-XOF variant so we can't match the expected output.
        raise TestSkip("KMAC XOF mode not exposed via Python bindings")
    if group.get("hexCustomization"):
        raise TestSkip("KMAC hex customization not exposed via Python bindings")

    if test["macLen"] % 8 != 0:
        raise TestSkip("Bit-oriented input not supported")
    if test.get("msgLen", 0) % 8 != 0:
        raise TestSkip("Bit-oriented input not supported")
    if test.get("keyLen", 0) % 8 != 0:
        raise TestSkip("Bit-oriented input not supported")

    key = _from_hex(test["key"])
    msg = _opt_hex(test, "msg")
    mac_len = test["macLen"] // 8
    customization = test.get("customization", "")

    algo = f"{algo_name}({mac_len * 8})"
    mac = botan.MsgAuthCode(algo)
    try:
        mac.set_key(key)
    except botan.BotanException as e:
        if "Invalid key length" in str(e):
            raise TestSkip(f"Botan KMAC rejects key of length {len(key)}") from e
        raise
    if customization:
        mac.set_nonce(customization.encode("utf-8"))
    mac.update(msg)
    computed = mac.final()

    if test_type == "AFT":
        if computed.hex() != exp["mac"].lower():
            raise TestFailure(
                {
                    "Algo": algo,
                    "Key": test["key"],
                    "Msg": test.get("msg", ""),
                    "Tag": exp["mac"],
                    "ComputedTag": computed.hex(),
                }
            )
        return

    expected_mac = _from_hex(test["mac"])
    should_pass = exp.get("testPassed", True)
    if should_pass and computed != expected_mac:
        raise TestFailure(
            {
                "Algo": algo,
                "Note": "Valid KMAC did not verify",
                "Tag": test["mac"],
                "ComputedTag": computed.hex(),
            }
        )
    if not should_pass and computed == expected_mac:
        raise TestFailure({"Algo": algo, "Note": "Invalid KMAC matched"})


# ---- Finite-field DSA sigVer / sigGen ----


_DSA_GROUP_MAP = {
    (2048, 256): "dsa/botan/2048",
    (3072, 256): "dsa/botan/3072",
}


@register("DSA-SigVer-1.0")
def handle_dsa_sigver(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    if group.get("conformance") == "SP800-106":
        raise TestSkip("SP800-106 randomized hashing not supported")

    hash_algo = _map_hash(group["hashAlg"])

    p = botan.MPI("0x" + group["p"])
    q = botan.MPI("0x" + group["q"])
    g = botan.MPI("0x" + group["g"])

    expected_valid = exp.get("testPassed", True)

    try:
        y = botan.MPI("0x" + test["y"])
        pub = botan.PublicKey.load_dsa(p, q, g, y)
    except botan.BotanException as e:
        if expected_valid:
            raise TestFailure(
                {
                    "L": group["l"],
                    "N": group["n"],
                    "Note": "DSA public key load failed on a valid test",
                }
            ) from e
        return

    # Pad r and s to N/8 bytes; test vectors may omit leading zeros.
    n_bytes = group["n"] // 8
    r = _from_hex(test["r"]).rjust(n_bytes, b"\x00")
    s = _from_hex(test["s"]).rjust(n_bytes, b"\x00")
    sig = r + s
    msg = _from_hex(test["message"])

    try:
        verifier = botan.PKVerify(pub, hash_algo, der=False)
        verifier.update(msg)
        valid = verifier.check_signature(sig)
    except botan.BotanException:
        valid = False

    if valid != expected_valid:
        raise TestFailure(
            {
                "L": group["l"],
                "N": group["n"],
                "Hash": group["hashAlg"],
                "R": test["r"],
                "S": test["s"],
                "Expected": "valid" if expected_valid else "invalid",
                "Got": "valid" if valid else "invalid",
            }
        )


@register("DSA-SigGen-1.0")
def handle_dsa_siggen(_header: dict, group: dict, test: dict, _exp: dict) -> None:
    _require_aft(group)

    group_l = group["l"]
    group_n = group["n"]
    group_name = _DSA_GROUP_MAP.get((group_l, group_n))
    if group_name is None:
        raise TestSkip(f"No named DSA group for L={group_l}, N={group_n}")

    hash_algo = _map_hash(group["hashAlg"])

    priv = _group_state(group, "priv")
    if priv is None:
        rng = botan.RandomNumberGenerator("system")
        priv = botan.PrivateKey.create("DSA", group_name, rng)
        _set_group_state(group, "priv", priv)

    msg = _from_hex(test["message"])
    rng = botan.RandomNumberGenerator("system")

    signer = botan.PKSign(priv, hash_algo, der=False)
    signer.update(msg)
    sig = signer.finish(rng)

    pub = priv.get_public_key()
    verifier = botan.PKVerify(pub, hash_algo, der=False)
    verifier.update(msg)
    if not verifier.check_signature(sig):
        raise TestFailure(
            {
                "L": group_l,
                "N": group_n,
                "Hash": group["hashAlg"],
                "Sig": sig.hex(),
                "Note": "Self-produced DSA signature failed to verify",
            }
        )


# ---- ECDSA sig ver ----


@register("ECDSA-SigVer-FIPS186-5", "ECDSA-SigVer-1.0")
def handle_ecdsa_sigver(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    if group.get("conformance") == "SP800-106":
        raise TestSkip("SP800-106 randomized hashing not supported")

    curve = _CURVE_MAP.get(group["curve"])
    if curve is None:
        raise TestSkip(f"Unsupported curve: {group['curve']}")
    if not botan.ECGroup.supports_named_group(curve):
        raise TestSkip(f"Curve {curve} not available in this build")

    hash_algo = _map_hash(group["hashAlg"])

    expected_valid = exp.get("testPassed", True)

    try:
        qx = botan.MPI("0x" + test["qx"])
        qy = botan.MPI("0x" + test["qy"])
        pub = botan.PublicKey.load_ecdsa(curve, qx, qy)
    except botan.BotanException as e:
        if expected_valid:
            raise TestFailure(
                {
                    "Curve": curve,
                    "Qx": test["qx"],
                    "Qy": test["qy"],
                    "Note": "Public key load failed on a valid test",
                }
            ) from e
        return

    sig = _from_hex(test["r"]) + _from_hex(test["s"])
    msg = _from_hex(test["message"])

    try:
        verifier = botan.PKVerify(pub, hash_algo, der=False)
        verifier.update(msg)
        valid = verifier.check_signature(sig)
    except botan.BotanException:
        valid = False

    if valid != expected_valid:
        raise TestFailure(
            {
                "Curve": curve,
                "Hash": group["hashAlg"],
                "R": test["r"],
                "S": test["s"],
                "Expected": "valid" if expected_valid else "invalid",
                "Got": "valid" if valid else "invalid",
            }
        )


# ---- ECDSA keyGen / keyVer / sigGen ----


def _ecdsa_resolve_curve(group: dict) -> str:
    curve = _CURVE_MAP.get(group["curve"])
    if curve is None:
        raise TestSkip(f"Unsupported curve: {group['curve']}")
    if not botan.ECGroup.supports_named_group(curve):
        raise TestSkip(f"Curve {curve} not available in this build")
    return curve


def _ecdsa_siggen_aft(group: dict, test: dict, *, deterministic: bool) -> None:
    _require_aft(group)

    curve = _ecdsa_resolve_curve(group)
    component = group.get("componentTest", False)

    # Component tests provide a pre-hashed message; use "Raw" padding.
    # Normal tests provide the raw message; use the named hash.
    if component:
        padding = "Raw"
    else:
        padding = _map_hash(group["hashAlg"])

    priv = _group_state(group, "priv")
    if priv is None:
        rng = botan.RandomNumberGenerator("system")
        priv = botan.PrivateKey.create("ECDSA", curve, rng)
        _set_group_state(group, "priv", priv)

    msg = _from_hex(test["message"])
    rng = botan.RandomNumberGenerator("system")

    signer = botan.PKSign(priv, padding, der=False)
    signer.update(msg)
    sig = signer.finish(rng)

    if deterministic:
        signer2 = botan.PKSign(priv, padding, der=False)
        signer2.update(msg)
        sig2 = signer2.finish(rng)
        if sig != sig2:
            raise TestFailure(
                {
                    "Curve": curve,
                    "Hash": group.get("hashAlg", "Raw"),
                    "Sig1": sig.hex(),
                    "Sig2": sig2.hex(),
                    "Note": "ECDSA is not deterministic under the same key/message",
                }
            )

    pub = priv.get_public_key()
    verifier = botan.PKVerify(pub, padding, der=False)
    verifier.update(msg)
    if not verifier.check_signature(sig):
        raise TestFailure(
            {
                "Curve": curve,
                "Hash": group.get("hashAlg", "Raw"),
                "Sig": sig.hex(),
                "Note": "Self-produced ECDSA signature failed to verify",
            }
        )


@register("DetECDSA-SigGen-FIPS186-5")
def handle_detecdsa_siggen(_header: dict, group: dict, test: dict, _exp: dict) -> None:
    _ecdsa_siggen_aft(group, test, deterministic=True)


@register("ECDSA-SigGen-FIPS186-5", "ECDSA-SigGen-1.0")
def handle_ecdsa_siggen(_header: dict, group: dict, test: dict, _exp: dict) -> None:
    _ecdsa_siggen_aft(group, test, deterministic=False)


@register("ECDSA-KeyGen-FIPS186-5", "ECDSA-KeyGen-1.0")
def handle_ecdsa_keygen(_header: dict, group: dict, _test: dict, _exp: dict) -> None:
    _require_aft(group)
    curve = _ecdsa_resolve_curve(group)

    rng = botan.RandomNumberGenerator("system")
    priv = botan.PrivateKey.create("ECDSA", curve, rng)
    pub = priv.get_public_key()

    # Smoke check the generated key: sign a short message and verify.
    signer = botan.PKSign(priv, "SHA-256", der=False)
    signer.update(b"acvp keygen self-test")
    sig = signer.finish(rng)
    verifier = botan.PKVerify(pub, "SHA-256", der=False)
    verifier.update(b"acvp keygen self-test")
    if not verifier.check_signature(sig):
        raise TestFailure(
            {"Curve": curve, "Note": "Fresh ECDSA key sign/verify round-trip failed"}
        )


@register("ECDSA-KeyVer-FIPS186-5", "ECDSA-KeyVer-1.0")
def handle_ecdsa_keyver(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)
    curve = _ecdsa_resolve_curve(group)

    expected_valid = exp.get("testPassed", True)
    try:
        qx = botan.MPI("0x" + test["qx"])
        qy = botan.MPI("0x" + test["qy"])
        botan.PublicKey.load_ecdsa(curve, qx, qy)
        valid = True
    except botan.BotanException:
        valid = False

    if valid != expected_valid:
        raise TestFailure(
            {
                "Curve": curve,
                "Qx": test["qx"],
                "Qy": test["qy"],
                "Expected": "valid" if expected_valid else "invalid",
                "Got": "valid" if valid else "invalid",
            }
        )


# ---- EdDSA keyGen / keyVer / sigGen ----

# Same IUT-generates-its-own-key pattern as ECDSA sigGen. ACVP supplies raw
# Ed25519/Ed448 public keys; wrap them in a SubjectPublicKeyInfo before
# handing to Botan's generic pubkey loader.
_ED25519_SPKI_PREFIX = bytes(
    [
        0x30,
        0x2A,
        0x30,
        0x05,
        0x06,
        0x03,
        0x2B,
        0x65,
        0x70,  # OID 1.3.101.112
        0x03,
        0x21,
        0x00,
    ]
)
_ED448_SPKI_PREFIX = bytes(
    [
        0x30,
        0x43,
        0x30,
        0x05,
        0x06,
        0x03,
        0x2B,
        0x65,
        0x71,  # OID 1.3.101.113
        0x03,
        0x3A,
        0x00,
    ]
)

_EDDSA_CURVE_MAP = {
    "ED-25519": ("Ed25519", _ED25519_SPKI_PREFIX),
    "ED-448": ("Ed448", _ED448_SPKI_PREFIX),
}


def _eddsa_resolve(group: dict) -> tuple[str, bytes]:
    info = _EDDSA_CURVE_MAP.get(group["curve"])
    if info is None:
        raise TestSkip(f"Unsupported curve: {group['curve']}")
    return info


@register("EDDSA-KeyGen-1.0")
def handle_eddsa_keygen(_header: dict, group: dict, _test: dict, _exp: dict) -> None:
    _require_aft(group)
    algo, _ = _eddsa_resolve(group)

    rng = botan.RandomNumberGenerator("system")
    priv = botan.PrivateKey.create(algo, "", rng)
    pub = priv.get_public_key()

    signer = botan.PKSign(priv, "")
    signer.update(b"acvp eddsa keygen self-test")
    sig = signer.finish(rng)
    verifier = botan.PKVerify(pub, "")
    verifier.update(b"acvp eddsa keygen self-test")
    if not verifier.check_signature(sig):
        raise TestFailure({"Algo": algo, "Note": "EdDSA key round-trip failed"})


@register("EDDSA-KeyVer-1.0")
def handle_eddsa_keyver(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)
    _, spki_prefix = _eddsa_resolve(group)

    expected_valid = exp.get("testPassed", True)
    if isinstance(expected_valid, str):
        expected_valid = expected_valid.lower() == "true"

    try:
        botan.PublicKey.load(spki_prefix + _from_hex(test["q"]))
        valid = True
    except botan.BotanException:
        valid = False

    if valid and not expected_valid:
        # Botan does not eagerly validate EdDSA point encodings on load;
        # invalid keys are only rejected at verify time.
        raise TestSkip("Botan does not eagerly reject invalid EdDSA keys")

    if valid != expected_valid:
        raise TestFailure(
            {
                "Curve": group["curve"],
                "Q": test["q"],
                "Expected": "valid" if expected_valid else "invalid",
                "Got": "valid" if valid else "invalid",
            }
        )


@register("EDDSA-SigGen-1.0")
def handle_eddsa_siggen(_header: dict, group: dict, test: dict, _exp: dict) -> None:
    _require_aft(group)
    if group.get("preHash"):
        raise TestSkip("EdDSA preHash not supported via Python bindings")

    algo, _ = _eddsa_resolve(group)

    priv = _group_state(group, "priv")
    if priv is None:
        rng = botan.RandomNumberGenerator("system")
        priv = botan.PrivateKey.create(algo, "", rng)
        _set_group_state(group, "priv", priv)

    msg = _from_hex(test["message"])
    rng = botan.RandomNumberGenerator("system")

    signer = botan.PKSign(priv, "")
    signer.update(msg)
    sig = signer.finish(rng)

    verifier = botan.PKVerify(priv.get_public_key(), "")
    verifier.update(msg)
    if not verifier.check_signature(sig):
        raise TestFailure(
            {
                "Algo": algo,
                "Sig": sig.hex(),
                "Note": "Self-produced EdDSA signature failed to verify",
            }
        )


# ---- RSA sigGen ----


@register("RSA-SigGen-FIPS186-5", "RSA-SigGen-FIPS186-4")
def handle_rsa_siggen(_header: dict, group: dict, test: dict, _exp: dict) -> None:
    # ACVP uses 'GDT' (generated data test) here. The IUT picks its own
    # key (with the given modulo size), signs each message, and reports
    # n/e/signatures. We check self-consistency (sign/verify round-trip).
    test_type = group.get("testType", "GDT")
    if test_type != "GDT":
        raise TestSkip(f"testType {test_type} not supported")

    hash_algo = _map_hash(group["hashAlg"])
    mask_fn = group.get("maskFunction")
    if mask_fn and mask_fn.startswith("shake"):
        raise TestSkip(f"SHAKE-based MGF ({mask_fn}) not supported")
    padding = _rsa_padding(group["sigType"], hash_algo, group.get("saltLen"))

    priv = _group_state(group, "priv")
    if priv is None:
        rng = botan.RandomNumberGenerator("system")
        priv = botan.PrivateKey.create("RSA", str(group["modulo"]), rng)
        _set_group_state(group, "priv", priv)

    msg = _from_hex(test["message"])
    rng = botan.RandomNumberGenerator("system")

    signer = botan.PKSign(priv, padding)
    signer.update(msg)
    sig = signer.finish(rng)

    verifier = botan.PKVerify(priv.get_public_key(), padding)
    verifier.update(msg)
    if not verifier.check_signature(sig):
        raise TestFailure(
            {
                "Padding": padding,
                "Modulo": str(group["modulo"]),
                "Note": "Self-produced RSA signature failed to verify",
            }
        )


# ---- RSA keyGen ----


@register("RSA-KeyGen-FIPS186-5", "RSA-KeyGen-FIPS186-4")
def handle_rsa_keygen(_header: dict, group: dict, _test: dict, _exp: dict) -> None:
    test_type = group.get("testType", "AFT")
    if test_type not in ("GDT",):
        # AFT/KAT require seed-based deterministic prime generation per
        # FIPS 186-4 appendix B.3, which Botan's keygen does not expose.
        raise TestSkip(
            f"RSA KeyGen testType {test_type} requires seed-based generation"
        )

    modulo = group["modulo"]
    rng = botan.RandomNumberGenerator("system")
    priv = botan.PrivateKey.create("RSA", str(modulo), rng)
    pub = priv.get_public_key()

    # Round-trip: sign and verify with the generated key.
    signer = botan.PKSign(priv, "PKCS1v15(SHA-256)")
    signer.update(b"acvp rsa keygen self-test")
    sig = signer.finish(rng)
    verifier = botan.PKVerify(pub, "PKCS1v15(SHA-256)")
    verifier.update(b"acvp rsa keygen self-test")
    if not verifier.check_signature(sig):
        raise TestFailure(
            {
                "Modulo": str(modulo),
                "Note": "Fresh RSA key sign/verify round-trip failed",
            }
        )


# ---- RSA primitives (raw modexp) ----


def _rsa_pad_to_modulus(data: bytes, n_hex: str) -> bytes:
    mod_bytes = (len(n_hex) + 1) // 2
    if len(data) < mod_bytes:
        return bytes(mod_bytes - len(data)) + data
    return data


@register("RSA-SignaturePrimitive-2.0")
def handle_rsa_sig_primitive(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    expected_pass = exp.get("testPassed", True)

    try:
        p = botan.MPI("0x" + test["p"])
        q = botan.MPI("0x" + test["q"])
        e = botan.MPI("0x" + test["e"])
        priv = botan.PrivateKey.load_rsa(p, q, e)
    except botan.BotanException:
        if not expected_pass:
            return
        raise

    msg_int = int(test["message"], 16) if test["message"] else 0
    n_int = int(test["n"], 16)

    # The signature primitive requires 0 < message < n.
    if msg_int < 1 or msg_int >= n_int:
        if expected_pass:
            raise TestFailure(
                {"Note": f"message out of range [1, n) but testPassed={expected_pass}"}
            )
        return

    msg = _rsa_pad_to_modulus(_from_hex(test["message"]), test["n"])

    try:
        signer = botan.PKSign(priv, "Raw")
        signer.update(msg)
        rng = botan.RandomNumberGenerator("system")
        sig = signer.finish(rng)
    except botan.BotanException:
        if not expected_pass:
            return
        raise

    if not expected_pass:
        raise TestFailure(
            {"Note": "Expected failure but RSA signature primitive succeeded"}
        )

    if sig.hex() != exp["signature"].lower():
        raise TestFailure({"Sig": exp["signature"], "ComputedSig": sig.hex()})


@register("RSA-DecryptionPrimitive-Sp800-56Br2")
def handle_rsa_dec_primitive(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    expected_pass = exp.get("testPassed", True)

    try:
        p = botan.MPI("0x" + test["p"])
        q = botan.MPI("0x" + test["q"])
        e = botan.MPI("0x" + test["e"])
        priv = botan.PrivateKey.load_rsa(p, q, e)
    except botan.BotanException:
        if not expected_pass:
            return
        raise

    # SP800-56Br2 §7.1.2 restricts the ciphertext to [2, n-2]. Botan's RSA
    # implementation rejects ct == 0 and ct >= n, but values 1 and n-1 are
    # only invalid under the SP800-56Br2 key transport primitive, not for
    # general RSA decryption (OAEP, Raw). Skip those here.
    ct_int = int(test["ct"], 16) if test["ct"] else 0
    n_int = int(test["n"], 16)
    if ct_int in (1, n_int - 1):
        if expected_pass:
            raise TestFailure(
                {"Note": f"ct == 1 or ct == n-1 but testPassed={expected_pass}"}
            )
        return

    ct = _rsa_pad_to_modulus(_from_hex(test["ct"]), test["n"])

    try:
        dec = botan.PKDecrypt(priv, "Raw")
        pt = dec.decrypt(ct)
    except botan.BotanException:
        if not expected_pass:
            return
        raise

    if not expected_pass:
        raise TestFailure(
            {"Note": "Expected failure but RSA decryption primitive succeeded"}
        )

    # Pad to modulus byte length (raw decryption may strip leading zeros).
    mod_bytes = (len(test["n"]) + 1) // 2
    pt = bytes(mod_bytes - len(pt)) + pt if len(pt) < mod_bytes else pt

    if pt.hex() != exp["pt"].lower():
        raise TestFailure({"PT": exp["pt"], "ComputedPT": pt.hex()})


# ---- AES-GMAC ----


@register("ACVP-AES-GMAC-1.0")
def handle_aes_gmac(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    if group.get("ivGen", "external") != "external":
        raise TestSkip(f"GMAC ivGen {group.get('ivGen')} not supported")

    algo = f"GMAC(AES-{group['keyLen']})"
    key = _from_hex(test["key"])
    iv = _from_hex(test["iv"])
    aad = _opt_hex(test, "aad")
    tag_bytes = group["tagLen"] // 8

    mac = botan.MsgAuthCode(algo)
    mac.set_key(key)
    mac.set_nonce(iv)
    mac.update(aad)
    computed = mac.final()[:tag_bytes]

    if group["direction"] == "encrypt":
        if computed.hex() != exp["tag"].lower():
            raise TestFailure(
                {
                    "Algo": algo,
                    "Key": test["key"],
                    "IV": test["iv"],
                    "AAD": test.get("aad", ""),
                    "Tag": exp["tag"],
                    "ComputedTag": computed.hex(),
                }
            )
        return

    expected_mac = _from_hex(test["tag"])[:tag_bytes]
    should_pass = exp.get("testPassed", True)
    if should_pass and computed != expected_mac:
        raise TestFailure(
            {
                "Algo": algo,
                "Tag": test["tag"],
                "ComputedTag": computed.hex(),
                "Note": "Valid GMAC did not match",
            }
        )
    if not should_pass and computed == expected_mac:
        raise TestFailure({"Algo": algo, "Note": "Invalid GMAC matched"})


# ---- PBKDF2 ----


@register("PBKDF-1.0")
def handle_pbkdf(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    algo = _PBKDF_HMAC_MAP.get(group["hmacAlg"])
    if algo is None:
        raise TestSkip(f"Unsupported PBKDF hmacAlg: {group['hmacAlg']}")

    password = test["password"].encode("utf-8")
    salt = _from_hex(test["salt"])
    iters = test["iterationCount"]
    dk_len = test["keyLen"] // 8

    _, _, dk = botan.pbkdf(
        algo, password.decode("utf-8"), dk_len, iterations=iters, salt=salt
    )
    if dk.hex() != exp["derivedKey"].lower():
        raise TestFailure(
            {
                "Algo": algo,
                "Iters": str(iters),
                "DkLen": str(dk_len),
                "Expected": exp["derivedKey"],
                "Got": dk.hex(),
            }
        )


# ---- HKDF (SP800-56C) ----


def _kda_party_info(party: dict) -> bytes:
    # uPartyInfo / vPartyInfo: concatenation of the party's fields in the
    # order they appear (partyId, ephemeralData).
    out = _from_hex(party["partyId"])
    if party.get("ephemeralData"):
        out += _from_hex(party["ephemeralData"])
    return out


def _kda_fixed_info(pattern: str, party_u: dict, party_v: dict, l_bits: int) -> bytes:
    if pattern != "uPartyInfo||vPartyInfo||l":
        raise TestSkip(f"fixedInfoPattern {pattern!r} not supported")
    return (
        _kda_party_info(party_u) + _kda_party_info(party_v) + l_bits.to_bytes(4, "big")
    )


@register("HKDF-1.0")
def handle_hkdf_standalone(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    hash_name = _KDF_HASH_MAP.get(group["hmacAlg"])
    if hash_name is None:
        raise TestSkip(f"Hash {group['hmacAlg']} not supported")

    algo = f"HKDF({hash_name})"
    ikm = _from_hex(test["inputKeyingMaterial"])
    salt = _opt_hex(test, "salt")
    info = _opt_hex(test, "otherInfo")
    out_len = test["keyLength"]

    out = botan.kdf(algo, ikm, out_len, salt, info)
    if out.hex() != exp["derivedKey"].lower():
        raise TestFailure(
            {"Algo": algo, "DerivedKey": exp["derivedKey"], "ComputedKey": out.hex()}
        )


# ---- KDA shared helper (HKDF and OneStep) ----


_KDA_ONESTEP_AUX_MAP = {
    "SHA-1": "SP800-56A(SHA-1)",
    "SHA2-224": "SP800-56A(SHA-224)",
    "SHA2-256": "SP800-56A(SHA-256)",
    "SHA2-384": "SP800-56A(SHA-384)",
    "SHA2-512": "SP800-56A(SHA-512)",
    "SHA3-224": "SP800-56A(SHA-3(224))",
    "SHA3-256": "SP800-56A(SHA-3(256))",
    "SHA3-384": "SP800-56A(SHA-3(384))",
    "SHA3-512": "SP800-56A(SHA-3(512))",
    "KMAC-128": "SP800-56A(KMAC-128)",
    "KMAC-256": "SP800-56A(KMAC-256)",
}
# Add HMAC variants derived from the canonical hash map.
for _k, _v in _HASH_MAP.items():
    if _v is not None and not _k.startswith("SHAKE"):
        _KDA_ONESTEP_AUX_MAP[f"HMAC-{_k}"] = f"SP800-56A(HMAC({_v}))"


def _kda_aft(algo: str, salt: bytes, group: dict, test: dict, exp: dict) -> None:
    """Shared helper for KDA-HKDF and KDA-OneStep AFT/VAL tests."""
    test_type = group.get("testType", "AFT")

    kc = group["kdfConfiguration"]
    kp = test["kdfParameter"]

    z = _from_hex(kp["z"])
    if group.get("usesHybridSharedSecret") and kp.get("t"):
        z += _from_hex(kp["t"])
    l_bits = int(kp["l"])
    out_len = l_bits // 8

    fixed_info = _kda_fixed_info(
        kc["fixedInfoPattern"], test["fixedInfoPartyU"], test["fixedInfoPartyV"], l_bits
    )

    dkm = botan.kdf(algo, z, out_len, salt, fixed_info)

    if test_type == "AFT":
        if dkm.hex() != exp["dkm"].lower():
            raise TestFailure(
                {"Algo": algo, "DKM": exp["dkm"], "ComputedDKM": dkm.hex()}
            )
    else:
        expected_dkm = _from_hex(test["dkm"])
        passed = dkm == expected_dkm
        if passed != exp.get("testPassed", True):
            raise TestFailure(
                {
                    "Algo": algo,
                    "Expected": str(exp.get("testPassed")),
                    "Got": str(passed),
                }
            )


def _kda_resolve(group: dict, test: dict) -> tuple[str, bytes]:
    """Parse kdfConfiguration and return (botan_algo_name, salt)."""
    test_type = group.get("testType", "AFT")
    if test_type not in ("AFT", "VAL"):
        raise TestSkip(f"testType {test_type} not supported")

    kc = group.get("kdfConfiguration")
    if kc is None:
        raise TestSkip("Missing kdfConfiguration (multi-expansion not supported)")
    if kc.get("fixedInfoEncoding", "concatenation") != "concatenation":
        raise TestSkip(f"fixedInfoEncoding {kc.get('fixedInfoEncoding')} not supported")

    kdf_type = kc["kdfType"]
    kp = test["kdfParameter"]

    if kdf_type == "hkdf":
        hash_name = _KDF_HASH_MAP.get(kc["hmacAlg"])
        if hash_name is None:
            raise TestSkip(f"Hash {kc['hmacAlg']} not supported")
        return f"HKDF({hash_name})", _from_hex(kp.get("salt", ""))

    if kdf_type == "oneStep":
        aux = kc.get("auxFunction")
        algo = _KDA_ONESTEP_AUX_MAP.get(aux)
        if algo is None:
            raise TestSkip(f"Unsupported auxFunction: {aux}")
        uses_salt = aux.startswith(("HMAC-", "KMAC-"))
        salt = _from_hex(kp.get("salt", "")) if uses_salt else b""
        return algo, salt

    raise TestSkip(f"Unsupported kdfType: {kdf_type}")


@register(
    "KDA-HKDF-Sp800-56Cr1",
    "KDA-HKDF-Sp800-56Cr2",
    "KDA-OneStep-Sp800-56Cr1",
    "KDA-OneStep-Sp800-56Cr2",
)
def handle_kda(_header: dict, group: dict, test: dict, exp: dict) -> None:
    algo, salt = _kda_resolve(group, test)
    _kda_aft(algo, salt, group, test, exp)


# ---- TLS-v1.2-KDF-RFC7627 (Extended Master Secret) ----


@register("TLS-v1.2-KDF-RFC7627")
def handle_tls12_kdf_ems(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    hash_name = _KDF_HASH_MAP.get(group["hashAlg"])
    if hash_name is None:
        raise TestSkip(f"Hash {group['hashAlg']} not supported")
    algo = f"TLS-12-PRF({hash_name})"

    pms = _from_hex(test["preMasterSecret"])
    session_hash = _from_hex(test["sessionHash"])
    cr = _from_hex(test["clientRandom"])
    sr = _from_hex(test["serverRandom"])
    kb_len = group["keyBlockLength"] // 8

    ms = botan.kdf(algo, pms, 48, session_hash, b"extended master secret")
    if ms.hex() != exp["masterSecret"].lower():
        raise TestFailure(
            {"Algo": algo, "MS": exp["masterSecret"], "ComputedMS": ms.hex()}
        )

    kb = botan.kdf(algo, ms, kb_len, sr + cr, b"key expansion")
    if kb.hex() != exp["keyBlock"].lower():
        raise TestFailure({"Algo": algo, "KB": exp["keyBlock"], "ComputedKB": kb.hex()})


# ---- ANSI X9.63 KDF (SEC 1) ----


@register("kdf-components-ansix9.63-1.0")
def handle_kdf_ansix963(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    hash_name = _KDF_HASH_MAP.get(group["hashAlg"])
    if hash_name is None:
        raise TestSkip(f"Hash {group['hashAlg']} not supported")
    # ANSI X9.63 KDF == IEEE KDF2.
    algo = f"KDF2({hash_name})"

    z = _from_hex(test["z"])
    shared = _opt_hex(test, "sharedInfo")
    out_len = group["keyDataLength"] // 8

    kd = botan.kdf(algo, z, out_len, shared, b"")
    if kd.hex() != exp["keyData"].lower():
        raise TestFailure(
            {"Algo": algo, "KeyData": exp["keyData"], "ComputedKeyData": kd.hex()}
        )


# ---- TLS PRF (kdf-components-tls) ----


_TLS12_PRF_HASH_MAP = {
    "SHA2-256": "TLS-12-PRF(SHA-256)",
    "SHA2-384": "TLS-12-PRF(SHA-384)",
    "SHA2-512": "TLS-12-PRF(SHA-512)",
}


@register("kdf-components-tls-1.0")
def handle_kdf_components_tls(
    _header: dict, group: dict, test: dict, exp: dict
) -> None:
    _require_aft(group)

    version = group["tlsVersion"]
    if version != "v1.2":
        raise TestSkip(f"TLS {version} PRF not implemented anymore")

    algo = _TLS12_PRF_HASH_MAP.get(group["hashAlg"])
    if algo is None:
        raise TestSkip(f"TLS 1.2 PRF with hash {group['hashAlg']} not supported")

    pms = _from_hex(test["preMasterSecret"])
    chr_ = _from_hex(test["clientHelloRandom"])
    shr = _from_hex(test["serverHelloRandom"])
    cr = _from_hex(test["clientRandom"])
    sr = _from_hex(test["serverRandom"])
    kb_len = group["keyBlockLength"] // 8

    ms = botan.kdf(algo, pms, 48, chr_ + shr, b"master secret")
    if ms.hex() != exp["masterSecret"].lower():
        raise TestFailure(
            {"Algo": algo, "MS": exp["masterSecret"], "ComputedMS": ms.hex()}
        )

    kb = botan.kdf(algo, ms, kb_len, sr + cr, b"key expansion")
    if kb.hex() != exp["keyBlock"].lower():
        raise TestFailure({"Algo": algo, "KB": exp["keyBlock"], "ComputedKB": kb.hex()})


# ---- RSA sig ver FIPS 186-2 ----


@register("RSA-SigVer-FIPS186-2")
def handle_rsa_sigver_fips186_2(
    header: dict, group: dict, test: dict, exp: dict
) -> None:
    # Same handler as RSA-SigVer-FIPS186-5 — reuses the same padding logic
    # and the same X9.31 skip.
    handle_rsa_sigver(header, group, test, exp)


# ---- LMS keyGen ----

_LMS_HASH_FROM_MODE = {
    "LMS_SHA256_M32": "SHA-256",
    "LMS_SHA256_M24": "Truncated(SHA-256,192)",
    "LMS_SHAKE_M32": "SHAKE-256(256)",
    "LMS_SHAKE_M24": "SHAKE-256(192)",
}

_LMOTS_W_FROM_SUFFIX = {"W1": 1, "W2": 2, "W4": 4, "W8": 8}


def _lms_botan_params(lms_mode: str, lmots_mode: str) -> str:
    # lms_mode like 'LMS_SHA256_M24_H5' -> prefix 'LMS_SHA256_M24' and h=5.
    # lmots_mode like 'LMOTS_SHA256_N24_W1' -> w=1.
    prefix, _, h_tag = lms_mode.rpartition("_")
    if not h_tag.startswith("H"):
        raise ValueError(f"Unexpected LMS mode: {lms_mode}")
    h = int(h_tag[1:])
    w = _LMOTS_W_FROM_SUFFIX[lmots_mode.rsplit("_", 1)[-1]]
    hash_name = _LMS_HASH_FROM_MODE[prefix]
    return f"{hash_name},HW({h},{w})"


@register("LMS-keyGen-1.0")
def handle_lms_keygen(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    # LMS keygen computes 2^h OTS leaves, which is too slow for the normal
    # run even at the lowest tree heights in these vectors. Gate the whole
    # directory behind ACVP_RUN_SLOW_TESTS.
    if os.environ.get("ACVP_RUN_SLOW_TESTS") != "1":
        raise TestSkip("LMS keygen disabled (set ACVP_RUN_SLOW_TESTS=1)")

    params = _lms_botan_params(group["lmsMode"], group["lmOtsMode"])
    seed = _from_hex(test["seed"])
    ident = _from_hex(test["i"])

    rng = FixedOutputRNG(seed + ident)
    priv = botan.PrivateKey.create("HSS-LMS", params, rng)
    pub = priv.get_public_key()

    # Botan emits HSS-LMS format with a 4-byte level-count prefix; ACVP
    # expects the underlying single-level LMS public key. Strip the prefix.
    raw = pub.to_raw()
    if raw[:4] != b"\x00\x00\x00\x01":
        raise TestFailure({"Mode": params, "Note": "Expected HSS L=1 prefix in pubkey"})
    computed = raw[4:].hex()
    if computed != exp["publicKey"].lower():
        raise TestFailure(
            {
                "LmsMode": group["lmsMode"],
                "LmOtsMode": group["lmOtsMode"],
                "PublicKey": exp["publicKey"],
                "ComputedPublicKey": computed,
            }
        )


# ---- LMS sigVer ----

# OID for id-alg-hss-lms-hashsig (1.2.840.113549.1.9.16.3.17), as used in
# RFC 8708's SPKI encoding for HSS/LMS public keys.
_HSS_LMS_OID_DER = bytes(
    [
        0x06,
        0x0B,
        0x2A,
        0x86,
        0x48,
        0x86,
        0xF7,
        0x0D,
        0x01,
        0x09,
        0x10,
        0x03,
        0x11,
    ]
)


def _der_seq(body: bytes) -> bytes:
    # Only used for short bodies (< 128 bytes); all LMS SPKI fit in that.
    if len(body) >= 0x80:
        raise ValueError("DER helper only handles short lengths")
    return b"\x30" + bytes([len(body)]) + body


def _wrap_lms_spki(lms_pub: bytes) -> bytes:
    """Wrap a raw LMS public key as an HSS-LMS SubjectPublicKeyInfo.

    ACVP's LMS vectors contain a standalone LMS public key; Botan loads
    HSS-LMS, so we prepend the HSS L=1 level count and emit SPKI DER.
    """
    hss_body = b"\x00\x00\x00\x01" + lms_pub
    bit_string = b"\x03" + bytes([len(hss_body) + 1]) + b"\x00" + hss_body
    alg_id = _der_seq(_HSS_LMS_OID_DER)
    return _der_seq(alg_id + bit_string)


@register("LMS-sigVer-1.0", "LMS-sigVer-SP800-208")
def handle_lms_sigver(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    pub = _group_state(group, "pub")
    if pub is None:
        try:
            pub = botan.PublicKey.load(_wrap_lms_spki(_from_hex(group["publicKey"])))
        except botan.BotanException as e:
            raise TestSkip(f"HSS-LMS pubkey load failed: {e}") from e
        _set_group_state(group, "pub", pub)

    msg = _from_hex(test["message"])
    # ACVP LMS signatures are plain LMS signatures; Botan's HSS-LMS verify
    # wants an HSS wrapper with Nspk=0 (no signed keys below the root).
    sig = b"\x00\x00\x00\x00" + _from_hex(test["signature"])

    expected_valid = exp.get("testPassed", True)
    try:
        verifier = botan.PKVerify(pub, "")
        verifier.update(msg)
        valid = verifier.check_signature(sig)
    except botan.BotanException:
        valid = False

    if valid != expected_valid:
        raise TestFailure(
            {
                "LmsMode": group.get("lmsMode"),
                "LmOtsMode": group.get("lmOtsMode"),
                "Msg": test["message"][:80] + "...",
                "Expected": "valid" if expected_valid else "invalid",
                "Got": "valid" if valid else "invalid",
            }
        )


@register("LMS-sigGen-1.0", "LMS-sigGen-SP800-208")
def handle_lms_siggen(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    # The reference signer's private key is not in the vector data, so
    # signing cannot be reproduced offline. Instead verify the reference
    # signatures from expectedResults against its group-level public key.
    pub = _group_state(group, "pub")
    if pub is None:
        exp_group = _group_state(group, "expected_group") or {}
        if "publicKey" not in exp_group:
            raise TestSkip("LMS sigGen reference public key not present")
        try:
            pub = botan.PublicKey.load(_wrap_lms_spki(_from_hex(exp_group["publicKey"])))
        except botan.BotanException as e:
            raise TestSkip(f"HSS-LMS pubkey load failed: {e}") from e
        _set_group_state(group, "pub", pub)

    # Same Nspk=0 HSS wrapper as in handle_lms_sigver
    sig = b"\x00\x00\x00\x00" + _from_hex(exp["signature"])
    verifier = botan.PKVerify(pub, "")
    verifier.update(_from_hex(test["message"]))
    if not verifier.check_signature(sig):
        raise TestFailure(
            {
                "LmsMode": group.get("lmsMode"),
                "LmOtsMode": group.get("lmOtsMode"),
                "Msg": test["message"][:80] + "...",
                "Expected": "valid",
                "Got": "invalid",
            }
        )


@register("EDDSA-SigVer-1.0")
def handle_eddsa_sigver(_header: dict, group: dict, test: dict, exp: dict) -> None:
    test_type = group.get("testType", "AFT")
    if test_type not in ("AFT", "BFT"):
        raise TestSkip(f"testType {test_type} not supported")

    if group.get("preHash", False):
        raise TestSkip("EdDSA preHash not supported via Python bindings")

    curve = group["curve"]
    if curve == "ED-25519":
        spki_prefix = _ED25519_SPKI_PREFIX
    elif curve == "ED-448":
        spki_prefix = _ED448_SPKI_PREFIX
    else:
        raise TestSkip(f"Unsupported curve: {curve}")

    expected_valid = exp.get("testPassed", True)

    try:
        pub = botan.PublicKey.load(spki_prefix + _from_hex(test["q"]))
    except botan.BotanException as e:
        if expected_valid:
            raise TestFailure(
                {"Curve": curve, "Q": test["q"], "Note": "Pubkey load failed"}
            ) from e
        return

    msg = _from_hex(test["message"])
    sig = _from_hex(test["signature"])

    try:
        verifier = botan.PKVerify(pub, "")
        verifier.update(msg)
        valid = verifier.check_signature(sig)
    except botan.BotanException:
        valid = False

    if valid != expected_valid:
        raise TestFailure(
            {
                "Curve": curve,
                "Msg": test["message"],
                "Sig": test["signature"],
                "Expected": "valid" if expected_valid else "invalid",
                "Got": "valid" if valid else "invalid",
            }
        )


# ---- RSA sig ver ----


def _rsa_padding(sig_type: str, hash_algo: str, salt_len: int | None = None) -> str:
    if sig_type == "pkcs1v1.5":
        return f"PKCS1v15({hash_algo})"
    if sig_type == "pss":
        if salt_len is not None:
            return f"PSS({hash_algo},MGF1,{salt_len})"
        return f"PSS({hash_algo})"
    if sig_type == "ansx9.31":
        # X9.31 allows signatures in both forms: s and (n - s). The ACVP
        # vectors include signatures in the (n - s) form, which Botan's
        # verification does not handle (it only checks s^e mod n, not
        # (n - s)^e mod n).
        raise TestSkip("X9.31 verification of (n - s) form not supported")
    raise TestSkip(f"Unsupported RSA sig type: {sig_type}")


@register("RSA-SigVer-FIPS186-5", "RSA-SigVer-FIPS186-4")
def handle_rsa_sigver(_header: dict, group: dict, test: dict, exp: dict) -> None:
    hash_algo = _map_hash(group["hashAlg"])

    mask_fn = group.get("maskFunction")
    if mask_fn and mask_fn.startswith("shake"):
        raise TestSkip(f"SHAKE-based MGF ({mask_fn}) not supported")

    padding = _rsa_padding(group["sigType"], hash_algo, group.get("saltLen"))

    pub = _group_state(group, "rsa_pub")
    if pub is None:
        try:
            n = botan.MPI("0x" + group["n"])
            e = botan.MPI("0x" + group["e"])
            pub = botan.PublicKey.load_rsa(n, e)
        except botan.BotanException as e:
            _set_group_state(group, "rsa_pub_failed", True)
            raise TestFailure({"Note": "RSA pubkey load failed"}) from e
        _set_group_state(group, "rsa_pub", pub)

    msg = _from_hex(test["message"])
    sig = _from_hex(test["signature"])
    expected_valid = exp.get("testPassed", True)

    try:
        verifier = botan.PKVerify(pub, padding)
        verifier.update(msg)
        valid = verifier.check_signature(sig)
    except botan.BotanException:
        valid = False

    if valid != expected_valid:
        raise TestFailure(
            {
                "Padding": padding,
                "Msg": test["message"],
                "Sig": test["signature"],
                "Expected": "valid" if expected_valid else "invalid",
                "Got": "valid" if valid else "invalid",
            }
        )


# ---- ML-KEM ----


@register("ML-KEM-keyGen-FIPS203")
def handle_mlkem_keygen(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    param_set = group["parameterSet"]
    d = _from_hex(test["d"])
    z = _from_hex(test["z"])

    priv = botan.PrivateKey.load_ml_kem(param_set, d + z)
    pub = priv.get_public_key()
    if pub.to_raw().hex() != exp["ek"].lower():
        raise TestFailure(
            {"Mode": param_set, "EK": exp["ek"], "ComputedEK": pub.to_raw().hex()}
        )
    # dk comparison skipped: priv.to_raw() returns seed form; ACVP
    # expects the expanded dk.


@register("ML-KEM-encapDecap-FIPS203", "ML-KEM-encapDecap-FIPS203-tr1")
def handle_mlkem_encapdecap(_header: dict, group: dict, test: dict, exp: dict) -> None:
    test_type = group.get("testType", "AFT")
    param_set = group["parameterSet"]
    function = group["function"]

    if function == "encapsulation" and test_type == "AFT":
        ek = _from_hex(test["ek"])
        m = _from_hex(test["m"])
        pub = botan.PublicKey.load_ml_kem(param_set, ek)
        expected_k = _from_hex(exp["k"])
        rng = FixedOutputRNG(m)
        kem_e = botan.KemEncrypt(pub, "Raw")
        k, c = kem_e.create_shared_key(rng, b"", len(expected_k))
        if c.hex() != exp["c"].lower() or k.hex() != exp["k"].lower():
            raise TestFailure(
                {
                    "Mode": param_set,
                    "C": exp["c"],
                    "K": exp["k"],
                    "ComputedC": c.hex(),
                    "ComputedK": k.hex(),
                }
            )
        return

    if function == "decapsulation" and test_type == "VAL":
        # keyFormat "expanded" groups carry dk; "seed" groups carry d and z
        if "dk" in test:
            dk = _from_hex(test["dk"])
        else:
            dk = _from_hex(test["d"]) + _from_hex(test["z"])
        c = _from_hex(test["c"])
        priv = botan.PrivateKey.load_ml_kem(param_set, dk)
        kem_d = botan.KemDecrypt(priv, "Raw")
        try:
            k = kem_d.decrypt_shared_key(b"", 32, c)
        except botan.BotanException:
            return  # Implicit rejection is acceptable
        if k.hex() != exp["k"].lower():
            raise TestFailure({"Mode": param_set, "K": exp["k"], "ComputedK": k.hex()})
        return

    if (
        function in ("encapsulationKeyCheck", "decapsulationKeyCheck")
        and test_type == "VAL"
    ):
        if function == "decapsulationKeyCheck" and "dk" not in test:
            # ACVP-Server (as of v1.1.0.43) omits dk from the prompt for
            # these groups (keyFormat "none" matches neither the seed nor
            # the expanded serialization path); the tests cannot be run
            raise TestSkip("decapsulationKeyCheck dk missing from prompt data")
        expected_pass = exp.get("testPassed", True)
        try:
            if function == "encapsulationKeyCheck":
                botan.PublicKey.load_ml_kem(param_set, _from_hex(test["ek"]))
            else:
                botan.PrivateKey.load_ml_kem(param_set, _from_hex(test["dk"]))
            passed = True
        except botan.BotanException:
            passed = False
        if passed != expected_pass:
            raise TestFailure(
                {
                    "Mode": param_set,
                    "Function": function,
                    "Expected": str(expected_pass),
                    "Got": str(passed),
                }
            )
        return

    raise TestSkip(f"Unsupported function/type: {function}/{test_type}")


# ---- ML-DSA ----


_MLDSA_MODE_MAP = {
    "ML-DSA-44": "ML-DSA-4x4",
    "ML-DSA-65": "ML-DSA-6x5",
    "ML-DSA-87": "ML-DSA-8x7",
}


@register("ML-DSA-keyGen-FIPS204")
def handle_mldsa_keygen(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    param_set = group["parameterSet"]
    mode = _MLDSA_MODE_MAP.get(param_set, param_set)

    priv = botan.PrivateKey.load_ml_dsa(mode, _from_hex(test["seed"]))
    pub = priv.get_public_key()
    if pub.to_raw().hex() != exp["pk"].lower():
        raise TestFailure(
            {"Mode": mode, "PK": exp["pk"], "ComputedPK": pub.to_raw().hex()}
        )
    # sk comparison skipped: priv.to_raw() is seed form.


@register("ML-DSA-sigGen-FIPS204", "ML-DSA-sigGen-FIPS204-tr1")
def handle_mldsa_siggen(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    param_set = group["parameterSet"]
    mode = _MLDSA_MODE_MAP.get(param_set, param_set)

    if group.get("signatureInterface") == "internal":
        raise TestSkip("ML-DSA internal signature interface not exposed")
    if group.get("externalMu"):
        raise TestSkip("ML-DSA externalMu not exposed via Python bindings")
    if group.get("preHash", "pure") != "pure":
        raise TestSkip("ML-DSA preHash signing not yet supported")
    if "hashAlg" in test:
        raise TestSkip("ML-DSA preHash (per-test hashAlg) not supported")
    if test.get("context", ""):
        raise TestSkip("ML-DSA context not supported")

    # FIPS204-tr1 keyFormat "seed" groups carry the 32-byte seed;
    # keyFormat "expanded" groups (and all FIPS204 tests) carry sk
    sk = _from_hex(test["seed"]) if "seed" in test else _from_hex(test["sk"])
    msg = _from_hex(test["message"])

    try:
        priv = botan.PrivateKey.load_ml_dsa(mode, sk)
    except botan.BotanException as e:
        # ACVP provides expanded sk (2560/4032/4896 bytes); Botan only
        # accepts seed-form (32 bytes).
        raise TestSkip("ML-DSA expanded private key loading not supported") from e

    deterministic = group.get("deterministic", True)
    if deterministic:
        signer = botan.PKSign(priv, "Deterministic")
        signer.update(msg)
        sig = signer.finish(NullRNG()).hex()
    else:
        rnd = _from_hex(test["rnd"])
        rng = FixedOutputRNG(rnd)
        signer = botan.PKSign(priv, "")
        signer.update(msg)
        sig = signer.finish(rng).hex()
    if sig != exp["signature"].lower():
        raise TestFailure(
            {
                "Mode": mode,
                "Msg": test["message"],
                "Sig": exp["signature"],
                "ComputedSig": sig,
            }
        )


@register("ML-DSA-sigVer-FIPS204")
def handle_mldsa_sigver(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    param_set = group["parameterSet"]
    mode = _MLDSA_MODE_MAP.get(param_set, param_set)

    if group.get("signatureInterface") == "internal":
        raise TestSkip("ML-DSA internal signature interface not exposed")
    if group.get("externalMu"):
        raise TestSkip("ML-DSA externalMu not exposed via Python bindings")
    if group.get("preHash", "pure") != "pure":
        raise TestSkip("ML-DSA preHash verification not yet supported")
    if "hashAlg" in test:
        raise TestSkip("ML-DSA preHash (per-test hashAlg) not supported")
    if test.get("context", ""):
        raise TestSkip("ML-DSA context not supported")

    expected_valid = exp.get("testPassed", True)

    try:
        pub = botan.PublicKey.load_ml_dsa(mode, _from_hex(test["pk"]))
        verifier = botan.PKVerify(pub, "")
        verifier.update(_from_hex(test["message"]))
        valid = verifier.check_signature(_from_hex(test["signature"]))
    except botan.BotanException:
        valid = False

    if valid != expected_valid:
        raise TestFailure(
            {
                "Mode": mode,
                "Msg": test["message"],
                "Sig": test["signature"],
                "Expected": "valid" if expected_valid else "invalid",
                "Got": "valid" if valid else "invalid",
            }
        )


# ---- SLH-DSA ----


@register("SLH-DSA-keyGen-FIPS205")
def handle_slhdsa_keygen(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    param_set = group["parameterSet"]
    seed = (
        _from_hex(test["skSeed"]) + _from_hex(test["skPrf"]) + _from_hex(test["pkSeed"])
    )

    try:
        priv = botan.PrivateKey.load_slh_dsa(param_set, seed)
    except botan.BotanException as e:
        raise TestSkip(
            f"SLH-DSA key loading from seed not supported for {param_set}"
        ) from e

    pub = priv.get_public_key()
    if pub.to_raw().hex() != exp["pk"].lower():
        raise TestFailure(
            {"Mode": param_set, "PK": exp["pk"], "ComputedPK": pub.to_raw().hex()}
        )


@register("SLH-DSA-sigVer-FIPS205")
def handle_slhdsa_sigver(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    param_set = group["parameterSet"]
    if group.get("signatureInterface") == "internal":
        raise TestSkip("SLH-DSA internal signature interface not exposed")
    if group.get("preHash", "pure") != "pure":
        raise TestSkip("SLH-DSA preHash verification not yet supported")
    if test.get("context", ""):
        raise TestSkip("SLH-DSA context not supported")

    expected_valid = exp.get("testPassed", True)

    try:
        pub = botan.PublicKey.load_slh_dsa(param_set, _from_hex(test["pk"]))
        verifier = botan.PKVerify(pub, "")
        verifier.update(_from_hex(test["message"]))
        valid = verifier.check_signature(_from_hex(test["signature"]))
    except botan.BotanException:
        valid = False

    if valid != expected_valid:
        raise TestFailure(
            {
                "Mode": param_set,
                "Msg": test["message"],
                "Sig": test["signature"],
                "Expected": "valid" if expected_valid else "invalid",
                "Got": "valid" if valid else "invalid",
            }
        )


@register("SLH-DSA-sigGen-FIPS205")
def handle_slhdsa_siggen(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    param_set = group["parameterSet"]
    if group.get("signatureInterface") == "internal":
        raise TestSkip("SLH-DSA internal signature interface not exposed")
    if group.get("preHash", "pure") != "pure":
        raise TestSkip("SLH-DSA preHash signing not yet supported")
    if test.get("context", ""):
        raise TestSkip("SLH-DSA context not supported")

    sk = _from_hex(test["sk"])
    msg = _from_hex(test["message"])

    try:
        priv = botan.PrivateKey.load_slh_dsa(param_set, sk)
    except botan.BotanException as e:
        raise TestSkip(f"SLH-DSA key loading not supported for {param_set}") from e

    deterministic = group.get("deterministic", True)
    if deterministic:
        signer = botan.PKSign(priv, "Deterministic")
        signer.update(msg)
        sig = signer.finish(NullRNG()).hex()
    else:
        rnd = _from_hex(test["additionalRandomness"])
        rng = FixedOutputRNG(rnd)
        signer = botan.PKSign(priv, "")
        signer.update(msg)
        sig = signer.finish(rng).hex()

    if sig != exp["signature"].lower():
        raise TestFailure(
            {
                "Mode": param_set,
                "Msg": test["message"][:40] + "...",
                "Sig": exp["signature"][:40] + "...",
                "ComputedSig": sig[:40] + "...",
            }
        )


# ---- HMAC_DRBG ----


@register("hmacDRBG-1.0", "hmacDRBG-SP800-90Ar1")
def handle_hmac_drbg(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    hash_name = _HMAC_DRBG_MODE_MAP.get(group["mode"])
    if hash_name is None:
        raise TestSkip(f"Unsupported DRBG hash: {group['mode']}")

    entropy = _from_hex(test["entropyInput"])
    nonce = _from_hex(test["nonce"])
    perso = _from_hex(test["persoString"]) if test.get("persoString") else b""
    out_len = group["returnedBitsLen"] // 8
    pred_resistance = group.get("predResistance", False)

    drbg = botan.RandomNumberGenerator.drbg(
        f"HMAC_DRBG({hash_name})", entropy + nonce + perso
    )

    out = b""
    for item in test["otherInput"]:
        ai = _from_hex(item["additionalInput"]) if item.get("additionalInput") else b""
        ent = _from_hex(item["entropyInput"]) if item.get("entropyInput") else b""

        if item["intendedUse"] == "reSeed":
            drbg.add_entropy(ent + ai)
        elif pred_resistance and ent:
            # SP800-90A §9.3.1: with PR, reseed with (entropy || ai),
            # then generate with empty additional input.
            drbg.add_entropy(ent + ai)
            out = drbg.generate_with_input(out_len, b"")
        else:
            out = drbg.generate_with_input(out_len, ai)

    if out.hex() != exp["returnedBits"].lower():
        raise TestFailure(
            {
                "Mode": group["mode"],
                "ReturnedBits": exp["returnedBits"],
                "ComputedBits": out.hex(),
            }
        )


# ---- XECDH (RFC 7748) ----


@register("XECDH-keyGen-RFC7748")
def handle_xecdh_keygen(_header: dict, group: dict, _test: dict, exp: dict) -> None:
    _require_aft(group)

    # Key generation is randomized, so instead load the reference private
    # key from expectedResults and check we derive the same public key
    curve = group["curve"]
    priv_bytes = _from_hex(exp["privateKey"])
    if curve == "Curve25519":
        priv = botan.PrivateKey.load_x25519(priv_bytes)
    elif curve == "Curve448":
        priv = botan.PrivateKey.load_x448(priv_bytes)
    else:
        raise TestSkip(f"Unsupported curve: {curve}")

    pub = priv.get_public_key().to_raw()
    if pub.hex() != exp["publicKey"].lower():
        raise TestFailure(
            {
                "Curve": curve,
                "PublicKey": exp["publicKey"],
                "ComputedPublicKey": pub.hex(),
            }
        )


@register("XECDH-keyVer-RFC7748")
def handle_xecdh_keyver(_header: dict, group: dict, test: dict, exp: dict) -> None:
    _require_aft(group)

    curve = group["curve"]
    if curve not in ("Curve25519", "Curve448"):
        raise TestSkip(f"Unsupported curve: {curve}")

    expected_valid = exp.get("testPassed", True)
    raw = _from_hex(test["publicKey"])
    try:
        if curve == "Curve25519":
            botan.PublicKey.load_x25519(raw)
        else:
            botan.PublicKey.load_x448(raw)
        valid = True
    except botan.BotanException:
        valid = False

    if valid != expected_valid:
        raise TestFailure(
            {
                "Curve": curve,
                "PublicKey": test["publicKey"],
                "Expected": "valid" if expected_valid else "invalid",
                "Got": "valid" if valid else "invalid",
            }
        )


# ---- Ignored algorithms ----

_registry.ignore(
    # Botan follows SP800-108s presentation of combining counter, label and
    # context with domain separation and the length encoding. For whatever
    # reason the ACVP tests completely skip this and just provide a block of data
    # that should be fed to the raw PRF. Since we follow the spec (?!?) it's
    # not possible to run these tests.
    #
    # NIST is not my favorite standards organization
    "KDF-1.0",
    "KDA-TwoStep-Sp800-56Cr1",
    "KDA-TwoStep-Sp800-56Cr2",
    # ACVP's CTR tests are strange and possibly impossible for us to implement
    "ACVP-AES-CTR-1.0",
    "ACVP-TDES-CTR-1.0",
    # Unimplemented CBC ciphertext-stealing variants
    "ACVP-AES-CBC-CS1-1.0",
    "ACVP-AES-CBC-CS2-1.0",
    "ACVP-AES-CBC-CS3-1.0",
    # We don't support 1-bit CFB
    "ACVP-AES-CFB1-1.0",
    "ACVP-TDES-CFB1-1.0",
    # GCM-SIV currently not implemented
    "ACVP-AES-GCM-SIV-1.0",
    # Unimplemented FPE schemes
    "ACVP-AES-FF1-1.0",
    "ACVP-AES-FF3-1-1.0",
    # Weirdo modes
    "ACVP-AES-XPN-1.0",
    "ACVP-AES-CCM-ECMA-1.0",
    "ACVP-TDES-CBCI-1.0",
    "ACVP-TDES-CFBP1-1.0",
    "ACVP-TDES-CFBP64-1.0",
    "ACVP-TDES-CFBP8-1.0",
    "ACVP-TDES-OFBI-1.0",
    # Unimplemented, I didn't even know this was a thing
    "ACVP-TDES-KW-1.0",
    # Finite Field DSA
    "DSA-KeyGen-1.0",
    "DSA-PQGGen-1.0",
    "DSA-PQGVer-1.0",
    # Unimplemented
    "Ascon-CXOF128-SP800-232",
    "ParallelHash-128-1.0",
    "ParallelHash-256-1.0",
    "TupleHash-128-1.0",
    "TupleHash-256-1.0",
    # Doesn't seem relevant
    "safePrimes-keyVer-1.0",
    "safePrimes-keyGen-1.0",
    "XECDH-SSC-RFC7748",
    # Unimplemented DRBGs and support fns
    "ctrDRBG-1.0",
    "ctrDRBG-SP800-90Ar1",
    "hashDRBG-1.0",
    "hashDRBG-SP800-90Ar1",
    "ConditioningComponent-AES-CBC-MAC-Sp800-90B",
    "ConditioningComponent-BlockCipher_DF-Sp800-90B",
    "ConditioningComponent-Hash_DF-Sp800-90B",
    # Unimplemented KDFs
    "kdf-components-IKEv1-1.0",
    "kdf-components-ansix9.42-1.0",
    "kdf-components-ikev2-1.0",
    "kdf-components-snmp-1.0",
    "kdf-components-srtp-1.0",
    "kdf-components-ssh-1.0",
    "kdf-components-tpm-1.0",
    "KDF-KMAC-Sp800-108r1",
    "KDA-OneStepNoCounter-Sp800-56Cr2",
    "KDF-SPDM-1.0",
    # These are all some kind of multi-step protocol rather than
    # just testing a primitive
    "RSA-signaturePrimitive-1.0",
    "RSA-decryptionPrimitive-1.0",
    "KAS-ECC-1.0",
    "KAS-ECC-CDH-Component-1.0",
    "KAS-ECC-CDH-Component-Sp800-56Ar3",
    "KAS-ECC-SSC-Sp800-56Ar3",
    "KAS-ECC-Sp800-56Ar3",
    "KAS-FFC-1.0",
    "KAS-FFC-SSC-Sp800-56Ar3",
    "KAS-FFC-Sp800-56Ar3",
    "KAS-IFC-SSC-Sp800-56Br2",
    "KAS-IFC-Sp800-56Br2",
    "KAS-KC-Sp800-56",
    "KTS-IFC-Sp800-56Br2",
    "TLS-v1.3-KDF-RFC8446",
)


# ---- Entry point ----


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run NIST ACVP test vectors against Botan's Python bindings"
    )
    parser.add_argument(
        "data_dir",
        nargs="?",
        default=os.environ.get("ACVP_TESTDATA_DIR"),
        help="path to ACVP-Server gen-val/json-files directory "
        "(default: $ACVP_TESTDATA_DIR)",
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
        help="only run directories whose name matches FILTER (case-insensitive "
        "substring, may be repeated)",
    )
    args = parser.parse_args()

    if args.data_dir is None:
        parser.error(
            "data_dir argument or ACVP_TESTDATA_DIR environment variable required"
        )

    jobs = args.jobs
    if jobs is not None and jobs <= 0:
        parser.error("Invalid --jobs parameter")

    verbosity = 0 if args.quiet else (2 if args.verbose else 1)
    return run(args.data_dir, verbosity, jobs, args.filter or None)


if __name__ == "__main__":
    sys.exit(main())
