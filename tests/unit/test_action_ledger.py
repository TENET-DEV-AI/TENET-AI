"""Tamper detection for the action ledger."""

import sqlite3
import threading

import pytest

from services.security.ledger import (
    GENESIS_HASH,
    ActionLedger,
    generate_signing_key,
    load_private_key,
    load_public_key,
    private_key_to_pem,
    public_key_to_pem,
    verify_entries,
)


@pytest.fixture
def ledger(tmp_path):
    led = ActionLedger(tmp_path / "ledger.db", generate_signing_key())
    for i in range(5):
        led.append(
            entry_id=f"a{i}",
            actor="agent-1",
            action="send_email",
            tool="mailer",
            scope="org:acme",
            verdict="allow" if i % 2 == 0 else "block",
            reasoning=f"rule {i}",
        )
    return led


def _db(ledger):
    return sqlite3.connect(ledger._path)


def test_untouched_chain_verifies(ledger):
    result = ledger.verify()
    assert result.ok and result.checked == 5
    entries = ledger.entries()
    assert entries[0].prev_hash == GENESIS_HASH
    assert all(b.prev_hash == a.hash for a, b in zip(entries, entries[1:]))


def test_empty_ledger_verifies(tmp_path):
    led = ActionLedger(tmp_path / "empty.db", generate_signing_key())
    assert led.verify().ok


def test_editing_any_field_breaks_verification(ledger):
    for column, value in [
        ("verdict", "require_approval"),
        ("reasoning", "nothing to see"),
        ("actor", "someone-else"),
        ("action", "read_file"),
        ("tool", "other"),
        ("scope", "org:other"),
        ("timestamp", "2020-01-01T00:00:00+00:00"),
    ]:
        conn = _db(ledger)
        original = conn.execute(f"SELECT {column} FROM ledger WHERE seq = 3").fetchone()[0]
        conn.execute(f"UPDATE ledger SET {column} = ? WHERE seq = 3", (value,))
        conn.commit()
        result = ledger.verify()
        assert not result.ok, column
        assert result.broken_seq == 3
        conn.execute(f"UPDATE ledger SET {column} = ? WHERE seq = 3", (original,))
        conn.commit()
        conn.close()
    assert ledger.verify().ok


def test_deleting_a_middle_record_breaks_verification(ledger):
    conn = _db(ledger)
    conn.execute("DELETE FROM ledger WHERE seq = 2")
    conn.commit()
    result = ledger.verify()
    assert not result.ok and result.broken_seq == 3


def test_reordering_breaks_verification(ledger):
    entries = ledger.entries()
    swapped = [entries[0], entries[2], entries[1], *entries[3:]]
    result = verify_entries(swapped, ledger.public_key)
    assert not result.ok


def test_swapped_signature_is_rejected(ledger):
    entries = ledger.entries()
    conn = _db(ledger)
    conn.execute("UPDATE ledger SET signature = ? WHERE seq = 4", (entries[1].signature,))
    conn.commit()
    result = ledger.verify()
    assert not result.ok and result.broken_seq == 4
    assert "signature" in result.reason


def test_rewritten_chain_signed_with_another_key_fails_against_published_key(ledger, tmp_path):
    published = ledger.public_key
    attacker = ActionLedger(tmp_path / "forged.db", generate_signing_key())
    for entry in ledger.entries():
        attacker.append(
            entry_id=entry.id,
            actor=entry.actor,
            action=entry.action,
            tool=entry.tool,
            scope=entry.scope,
            verdict="allow",
            reasoning=entry.reasoning,
            timestamp=entry.timestamp,
        )
    assert attacker.verify().ok  # internally consistent...
    result = attacker.verify(public_key=published)  # ...but not signed by the real key
    assert not result.ok and result.broken_seq == 1


def test_invalid_verdict_is_rejected(ledger):
    with pytest.raises(ValueError):
        ledger.append(entry_id="x", actor="a", action="b", tool="c", verdict="maybe", reasoning="r")
    assert ledger.verify().checked == 5


def test_concurrent_appends_keep_one_chain(tmp_path):
    led = ActionLedger(tmp_path / "c.db", generate_signing_key())
    other = ActionLedger(tmp_path / "c.db", led._key)  # second handle, as a second process would be

    def writer(target, prefix):
        for i in range(15):
            target.append(
                entry_id=f"{prefix}{i}", actor="a", action="x", tool="t", verdict="allow", reasoning="r",
            )

    threads = [
        threading.Thread(target=writer, args=(led, "p")),
        threading.Thread(target=writer, args=(other, "q")),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    result = led.verify()
    assert result.ok and result.checked == 30


def test_key_pem_round_trip(tmp_path):
    key = generate_signing_key()
    assert private_key_to_pem(load_private_key(private_key_to_pem(key))) == private_key_to_pem(key)
    led = ActionLedger(tmp_path / "k.db", key)
    led.append(entry_id="1", actor="a", action="b", tool="c", verdict="allow", reasoning="r")
    published = load_public_key(public_key_to_pem(key))
    assert led.verify(public_key=published).ok
