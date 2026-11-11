"""Tamper-evident action ledger.

Every action an agent attempts, and the verdict it got, is appended as a record that carries the
hash of the record before it and an Ed25519 signature over its own hash. Editing a field, removing
or reordering a record, or swapping a signature breaks verification at that record.

The hash chain alone only proves the records are consistent with each other; someone with write
access to the database could rewrite the whole chain. The signature closes that gap: without the
private key they cannot produce records that verify against the published public key.

Not covered: dropping records off the *end* of the log leaves a valid shorter chain. Callers that
need to detect that should keep the latest ``seq``/``hash`` somewhere else (the compliance export
will do this).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

GENESIS_HASH = "0" * 64
VERDICTS = ("allow", "block", "require_approval")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger (
    seq        INTEGER PRIMARY KEY,
    id         TEXT NOT NULL,
    timestamp  TEXT NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    tool       TEXT NOT NULL,
    scope      TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    reasoning  TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL,
    signature  TEXT NOT NULL
)
"""

_HASHED_FIELDS = (
    "seq", "id", "timestamp", "actor", "action", "tool", "scope", "verdict", "reasoning", "prev_hash",
)


@dataclass(frozen=True)
class LedgerEntry:
    seq: int
    id: str
    timestamp: str
    actor: str
    action: str
    tool: str
    scope: str
    verdict: str
    reasoning: str
    prev_hash: str
    hash: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checked: int
    broken_seq: Optional[int] = None
    reason: str = ""


def generate_signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_key_to_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def public_key_to_pem(key: Union[Ed25519PrivateKey, Ed25519PublicKey]) -> bytes:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("not an Ed25519 private key")
    return key


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    return key


def _entry_hash(fields: dict[str, Any]) -> str:
    """SHA-256 over a canonical encoding of the hashed fields (sorted keys, no whitespace)."""
    payload = {name: fields[name] for name in _HASHED_FIELDS}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class ActionLedger:
    """Append-only, hash-chained, signed log of actions and verdicts, stored in SQLite."""

    def __init__(self, path: Union[str, Path], signing_key: Ed25519PrivateKey) -> None:
        self._path = str(path)
        self._key = signing_key
        self._lock = threading.Lock()
        conn = self._connect()
        try:
            conn.execute(_SCHEMA)
        finally:
            conn.close()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def append(
        self,
        *,
        entry_id: str,
        actor: str,
        action: str,
        tool: str,
        verdict: str,
        reasoning: str,
        scope: str = "",
        timestamp: Optional[str] = None,
    ) -> LedgerEntry:
        if verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {VERDICTS}, got {verdict!r}")
        stamp = timestamp or datetime.now(timezone.utc).isoformat()

        with self._lock:
            conn = self._connect()
            try:
                # BEGIN IMMEDIATE: two writers (even in separate processes) cannot both read the
                # same "last" record and fork the chain.
                conn.execute("BEGIN IMMEDIATE")
                last = conn.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
                fields: dict[str, Any] = {
                    "seq": (last["seq"] + 1) if last else 1,
                    "id": entry_id,
                    "timestamp": stamp,
                    "actor": actor,
                    "action": action,
                    "tool": tool,
                    "scope": scope,
                    "verdict": verdict,
                    "reasoning": reasoning,
                    "prev_hash": last["hash"] if last else GENESIS_HASH,
                }
                digest = _entry_hash(fields)
                signature = self._key.sign(bytes.fromhex(digest)).hex()
                entry = LedgerEntry(**fields, hash=digest, signature=signature)
                conn.execute(
                    "INSERT INTO ledger (seq, id, timestamp, actor, action, tool, scope, verdict,"
                    " reasoning, prev_hash, hash, signature)"
                    " VALUES (:seq, :id, :timestamp, :actor, :action, :tool, :scope, :verdict,"
                    " :reasoning, :prev_hash, :hash, :signature)",
                    entry.to_dict(),
                )
                conn.execute("COMMIT")
                return entry
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def entries(self) -> list[LedgerEntry]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM ledger ORDER BY seq").fetchall()
        finally:
            conn.close()
        return [LedgerEntry(**dict(row)) for row in rows]

    def verify(self, public_key: Optional[Ed25519PublicKey] = None) -> VerifyResult:
        """Walk the whole log. Pass the *published* public key to check against something an
        attacker with database access could not have replaced; defaults to this ledger's own key."""
        return verify_entries(self.entries(), public_key or self.public_key)


def verify_entries(entries: list[LedgerEntry], public_key: Ed25519PublicKey) -> VerifyResult:
    """Check order, hash chain, recomputed hashes and signatures. Stops at the first bad record."""
    expected_prev = GENESIS_HASH
    expected_seq = 1
    for checked, entry in enumerate(entries):
        if entry.seq != expected_seq:
            return VerifyResult(
                False, checked, entry.seq,
                f"expected seq {expected_seq}: a record was removed or reordered",
            )
        if entry.prev_hash != expected_prev:
            return VerifyResult(False, checked, entry.seq, "prev_hash does not match the previous record")
        if _entry_hash(entry.to_dict()) != entry.hash:
            return VerifyResult(False, checked, entry.seq, "record contents do not match its hash")
        try:
            public_key.verify(bytes.fromhex(entry.signature), bytes.fromhex(entry.hash))
        except (InvalidSignature, ValueError):
            return VerifyResult(False, checked, entry.seq, "signature is not valid for this record")
        expected_prev = entry.hash
        expected_seq += 1
    return VerifyResult(True, len(entries))
