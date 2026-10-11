import subprocess
import sys
import time

from test_ledger import begin, event, packet

from closure_engine.ledger import Ledger
from closure_engine.protocol import canonical


def test_real_process_death_during_uncommitted_receipt(run, tmp_path):
    ledger = begin(run, tmp_path)
    cp = ledger.checkpoint(run["keys"]["custodian"], run["binding"]["payload"]["created_at"])
    before = ledger.head
    candidate = event(run, ledger, "VERIFYING", receipt=run["receipts"][0])
    envelope_file = tmp_path / "envelope.json"
    envelope_file.write_bytes(canonical(candidate))
    ready = tmp_path / "worker-ready"
    code = (
        "import pathlib,sqlite3,sys,time; from closure_engine.protocol import strict_loads,digest;"
        "p=pathlib.Path(sys.argv[2]);raw=p.read_bytes();e=strict_loads(raw);"
        'db=sqlite3.connect(sys.argv[1],isolation_level=None);db.execute("BEGIN IMMEDIATE");'
        'db.execute("INSERT INTO events VALUES (?,?,?,?)",'
        '(e["payload"]["body"]["sequence"],e["payload"]["body"]["event_id"],raw,digest(e)));'
        'pathlib.Path(sys.argv[3]).write_text("uncommitted receipt inserted");time.sleep(300)'
    )
    worker = subprocess.Popen(
        [sys.executable, "-I", "-c", code, str(ledger.path), str(envelope_file), str(ready)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 10
        while not ready.exists() and worker.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ready.exists(), worker.communicate(timeout=1)
        worker.kill()
        worker.communicate(timeout=10)
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.communicate(timeout=10)
    reopened = Ledger(ledger.path, run["trust"], run["store"], checkpoint=cp)
    assert reopened.verify(cp) == before
    assert reopened.state("transaction-1") == "EXECUTING"
    result = packet(run, reopened, receipts=[])
    assert result["payload"]["body"]["verdict"] == "INDETERMINATE"
    reopened.append(event(run, reopened, "INDETERMINATE", packet=result), reopened.head)
    reopened.append(event(run, reopened, "RECOVERY_REQUIRED"), reopened.head)
    assert reopened.state("transaction-1") == "RECOVERY_REQUIRED"


def test_commit_then_lost_reply_is_idempotent_after_reopen(run, tmp_path):
    ledger = begin(run, tmp_path)
    cp = ledger.checkpoint(run["keys"]["custodian"], run["binding"]["payload"]["created_at"])
    old_head = ledger.head
    candidate = event(run, ledger, "VERIFYING", receipt=run["receipts"][0])
    expected = ledger.append(candidate, old_head)
    reopened = Ledger(ledger.path, run["trust"], run["store"], checkpoint=cp)
    assert reopened.append(candidate, old_head) == expected
    assert reopened.sequence == candidate["payload"]["body"]["sequence"]
