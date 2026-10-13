"""Proof-format compatibility promise (G5 of the 0.3.1 review).

``tests/fixtures/portable_v2_golden/`` holds a REAL ``ace.portable.v2`` proof produced by the
0.3.1 release wheel from a real loopback run (tools/make_golden_portable_proof.py), with the
operator pin in a separate file. Every later verifier must keep verifying this exact proof
offline. If this test goes red, the format changed without a version bump or the verifier
dropped its v2 reader; both break the promise in docs/PORTABLE_PROOF.md.
"""

import base64
import copy
import hashlib
import json
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

import pytest

import closure_engine
from closure_engine.protocol import ClosureError
from closure_engine.runtime.portable import VERSION, encode_bundle, read_bundle, verify_bundle

GOLDEN = Path(__file__).parent / "fixtures" / "portable_v2_golden"
SCOPE_FIELDS = {
    "mode",
    "minimum_verifier_version",
    "verification_notice",
    "transactions",
    "global_chain",
    "foreign_transaction_semantics",
}
PROOF_FIELDS = {"version", "transaction_id", "scope", "trust", "pages", "evaluators", "policies", "evidence"}


@pytest.fixture(scope="module")
def golden():
    manifest = json.loads((GOLDEN / "manifest.json").read_text(encoding="utf-8"))
    raw = (GOLDEN / "proof.json").read_bytes()
    # Fixture integrity: the committed bytes are the ones the manifest was written for.
    assert hashlib.sha256(raw).hexdigest() == manifest["proof_sha256"]
    assert len(raw) == manifest["proof_bytes"]
    pin = (GOLDEN / "trust-pin.txt").read_text(encoding="utf-8").strip()
    return manifest, read_bundle(GOLDEN / "proof.json"), pin


def test_golden_v2_proof_still_verifies_offline(golden):
    manifest, bundle, pin = golden
    result = verify_bundle(bundle, pin, expected_transaction=manifest["transaction_id"])
    assert result["closure"]["verdict"] == manifest["expected_verdict"] == "PROVEN"
    assert result["closure"]["artifact_hash"] == manifest["expected_artifact_hash"]
    assert result["verification_scope"]["transactions"] == [manifest["transaction_id"]]


def test_golden_v2_proof_verifies_through_the_shipped_command(golden):
    manifest, _, pin = golden
    done = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "closure_engine.runtime.portable",
            "--bundle",
            str(GOLDEN / "proof.json"),
            "--expected-trust-hash",
            pin,
            "--expected-transaction",
            manifest["transaction_id"],
            "--expected-artifact-hash",
            manifest["expected_artifact_hash"],
            "--require-proven",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["closure"]["verdict"] == "PROVEN"


def test_committed_format_shape_is_pinned(golden):
    _, bundle, _ = golden
    proof = bundle["portable"]
    assert proof["version"] == VERSION == "ace.portable.v2"
    assert set(proof) == PROOF_FIELDS
    assert set(proof["scope"]) == SCOPE_FIELDS
    assert proof["scope"]["minimum_verifier_version"] == "0.3.1"
    assert proof["scope"]["foreign_transaction_semantics"] == "NOT_EVALUATED"
    # A fresh export today must have the same shape as the committed one (no silent drift).
    assert set(json.loads(encode_bundle(bundle))["portable"]) == PROOF_FIELDS


@pytest.mark.parametrize(
    "mutate, code",
    [
        (lambda b: b["portable"].__setitem__("version", "ace.portable.v3"), "PORTABLE_BUNDLE_INVALID"),
        (
            lambda b: b["portable"]["scope"].__setitem__("minimum_verifier_version", "0.3.0"),
            "EXPORT_SCOPE_MISMATCH",
        ),
        (lambda b: b["portable"]["scope"].pop("verification_notice"), "EXPORT_SCOPE_MISMATCH"),
        (lambda b: b["portable"]["pages"][0]["events"].pop(), "CHECKPOINT_MISMATCH_OR_TRUNCATION"),
    ],
)
def test_altered_golden_proof_is_refused(golden, mutate, code):
    _, bundle, pin = golden
    altered = copy.deepcopy(bundle)
    mutate(altered)
    with pytest.raises(ClosureError) as info:
        verify_bundle(altered, pin)
    assert info.value.code == code, info.value


def test_altered_evidence_byte_is_refused(golden):
    _, bundle, pin = golden
    altered = copy.deepcopy(bundle)
    reference, encoded = next(iter(altered["portable"]["evidence"].items()))
    raw = bytearray(base64.b64decode(encoded))
    raw[0] ^= 0x01
    altered["portable"]["evidence"][reference] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(ClosureError) as info:
        verify_bundle(altered, pin)
    assert info.value.code == "EVIDENCE_HASH_MISMATCH"


def test_foreign_pin_is_refused(golden):
    _, bundle, _ = golden
    with pytest.raises(ClosureError) as info:
        verify_bundle(bundle, "sha256:" + "0" * 64)
    assert info.value.code == "TRUST_ANCHOR_MISMATCH"


def test_package_version_matches_the_distribution():
    assert closure_engine.__version__ == version("agentic-closure-engine")
    assert closure_engine.__version__ != "0.1.0"
