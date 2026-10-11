import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from closure_engine.contracts import freeze
from closure_engine.crypto import sign, verify
from closure_engine.protocol import ClosureError, canonical, digest, strict_loads


@pytest.mark.parametrize(
    "raw",
    [
        '{"a":1,"a":2}',
        '{"x":NaN}',
        '{"x":1.5}',
        '{"x":9007199254740992}',
        '{"x":"\\ud800"}',
        "[" * 40 + "0" + "]" * 40,
    ],
)
def test_A19_hostile_json(raw):
    with pytest.raises(ClosureError):
        strict_loads(raw)


def test_canonical_unicode_order_and_roundtrip():
    assert canonical({"z": 1, "a": "\u20ac"}) == b'{"a":"\xe2\x82\xac","z":1}'
    assert digest({"z": 1, "a": 2}) == digest({"a": 2, "z": 1})


def test_rfc8032_official_empty_message_vector():
    key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    )
    assert key.public_key().public_bytes_raw().hex() == (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    assert key.sign(b"").hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )


def test_A15_approval_cannot_freeze_changed_bytes(run):
    changed = copy.deepcopy(run["contract"])
    changed["intent"] = "different task"
    with pytest.raises(ClosureError):
        freeze(changed, run["approval"], run["trust"])


def test_frozen_contract_does_not_alias_input(run):
    old_hash = run["frozen"].hash
    run["contract"]["intent"] = "mutated after freeze"
    assert run["frozen"].hash == old_hash
    assert run["frozen"].data["intent"] == "one bounded correction"


def test_A28_signature_purpose_cannot_be_transplanted(run):
    with pytest.raises(ClosureError):
        verify(run["approval"], "closure-packet", run["trust"])


def test_actor_cannot_sign_approval(run):
    forged = sign(
        run["keys"]["actor"],
        "approval",
        run["approval"]["payload"]["body"],
        run["approval"]["payload"]["created_at"],
    )
    with pytest.raises(ClosureError):
        freeze(run["contract"], forged, run["trust"])


def test_unknown_contract_field_rejected(run):
    bad = copy.deepcopy(run["contract"])
    bad["execute_python"] = "anything"
    with pytest.raises(ClosureError):
        freeze(bad, run["approval"], run["trust"])
