"""Tests for audit log concurrency protection and cryptographic hash-chain continuity."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest

from aegis_gateway.storage import GENESIS_HASH, GatewayStore


def test_concurrent_threads_audit_chain_continuity(tmp_path: Path):
    """Verify that 20 concurrent threads writing audit records produce an unbroken hash chain."""
    db_path = tmp_path / "audit_concurrent.sqlite3"
    store = GatewayStore(db_path)

    workers = 20
    records_per_worker = 5
    total_expected = workers * records_per_worker

    def worker_task(worker_id: int):
        records = []
        for i in range(records_per_worker):
            rec = store.record_audit(
                username=f"worker_{worker_id}",
                role="ADMIN",
                action="CONCURRENT_ACTION",
                resource="test_resource",
                resource_id=f"res_{worker_id}_{i}",
                result="SUCCESS",
                details=f"Audit entry from worker {worker_id} iteration {i}",
                source_ip="10.0.0.1",
            )
            records.append(rec)
        return records

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(worker_task, w) for w in range(workers)]
        results = [f.result() for f in futures]

    # Verify total count
    all_inserted = [r for sublist in results for r in sublist]
    assert len(all_inserted) == total_expected

    # Verify integrity using the store's built-in verifier
    integrity = store.verify_audit_log_integrity()
    assert integrity["valid"] is True, f"Integrity check failed: {integrity.get('reason')}"
    assert integrity["count"] == total_expected
    assert integrity["first_corrupted_id"] is None

    # In-depth independent verification of continuity and uniqueness
    with store.connection() as con:
        rows = con.execute("SELECT rowid, * FROM admin_audit_log ORDER BY rowid ASC").fetchall()

    assert len(rows) == total_expected
    expected_prev = GENESIS_HASH
    seen_prev_hashes = set()

    for idx, row in enumerate(rows):
        prev_h = row["prev_hash"]
        rec_h = row["record_hash"]

        # 1. No duplicate prev_hash allowed (no forks)
        assert prev_h not in seen_prev_hashes, f"Duplicate prev_hash detected at index {idx}: {prev_h}"
        seen_prev_hashes.add(prev_h)

        # 2. Strict sequential continuity
        assert prev_h == expected_prev, f"Chain broken at index {idx}: expected {expected_prev}, got {prev_h}"

        # 3. Payload integrity check
        computed = store._compute_audit_hash(
            prev_hash=prev_h,
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            username=row["username"],
            role=row["role"],
            action=row["action"],
            resource=row["resource"],
            resource_id=row["resource_id"],
            result=row["result"],
            source_ip=row["source_ip"],
            details=row["details"],
        )
        assert computed == rec_h, f"Payload hash mismatch at index {idx}"
        expected_prev = rec_h


def test_multiple_independent_connections_concurrent_writes(tmp_path: Path):
    """Verify that multiple independent GatewayStore instances writing concurrently maintain chain continuity."""
    db_path = tmp_path / "multi_conn.sqlite3"

    # Seed one record
    initial_store = GatewayStore(db_path)
    initial_store.record_audit(
        username="system",
        role="SYSTEM",
        action="SEED",
        resource="system",
        result="SUCCESS",
        details="Initial genesis event",
    )

    num_stores = 5
    stores = [GatewayStore(db_path) for _ in range(num_stores)]
    writes_per_store = 6
    total_expected = 1 + (num_stores * writes_per_store)

    def write_task(store_idx: int, iteration: int):
        target_store = stores[store_idx]
        return target_store.record_audit(
            username=f"multi_user_{store_idx}",
            role="ADMIN",
            action="MULTI_CONN_ACTION",
            resource="database",
            resource_id=f"conn_{store_idx}_{iteration}",
            result="SUCCESS",
            details=f"Store instance {store_idx} write #{iteration}",
        )

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for s_idx in range(num_stores):
            for it in range(writes_per_store):
                futures.append(executor.submit(write_task, s_idx, it))
        for f in futures:
            f.result()

    # Verify overall integrity
    integrity = initial_store.verify_audit_log_integrity()
    assert integrity["valid"] is True, f"Integrity check failed: {integrity.get('reason')}"
    assert integrity["count"] == total_expected

    # Verify zero duplicate prev_hashes
    with initial_store.connection() as con:
        duplicates = con.execute(
            "SELECT prev_hash, COUNT(*) as c FROM admin_audit_log GROUP BY prev_hash HAVING c > 1"
        ).fetchall()
    assert len(duplicates) == 0, f"Found duplicate prev_hashes: {[dict(d) for d in duplicates]}"


def test_no_duplicate_predecessors_under_heavy_concurrency(tmp_path: Path):
    """Verify under heavy concurrency (25 threads) that no two records ever share a predecessor hash."""
    db_path = tmp_path / "heavy_concurrency.sqlite3"
    store = GatewayStore(db_path)

    threads = 25

    def single_write(idx: int):
        return store.record_audit(
            username=f"heavy_user_{idx}",
            role="OPERATOR",
            action="BURST_EVENT",
            resource="network",
            resource_id=str(idx),
            result="SUCCESS",
            details=f"Burst payload {idx}",
        )

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(single_write, i) for i in range(threads)]
        for f in futures:
            f.result()

    integrity = store.verify_audit_log_integrity()
    assert integrity["valid"] is True
    assert integrity["count"] == threads

    with store.connection() as con:
        prev_hashes = [r["prev_hash"] for r in con.execute("SELECT prev_hash FROM admin_audit_log").fetchall()]
    assert len(prev_hashes) == len(set(prev_hashes)), "Duplicate prev_hash detected in audit log!"


def test_audit_write_rollback_and_recovery(tmp_path: Path):
    """Verify that a failed write cleanly rolls back and subsequent writes maintain hash chain continuity."""
    db_path = tmp_path / "rollback_test.sqlite3"
    store = GatewayStore(db_path)

    # 1. Write an initial valid record
    first = store.record_audit(
        username="admin",
        role="ADMIN",
        action="BEFORE_FAIL",
        resource="system",
        result="SUCCESS",
        details="Pre-failure record",
    )
    first_hash = first["record_hash"]

    # 2. Simulate an insertion failure midway through record_audit
    original_compute = store._compute_audit_hash

    def failing_compute(*args, **kwargs):
        raise sqlite3.IntegrityError("Simulated write interruption")

    with patch.object(store, "_compute_audit_hash", side_effect=failing_compute):
        with pytest.raises(sqlite3.IntegrityError):
            store.record_audit(
                username="admin",
                role="ADMIN",
                action="FAILED_ACTION",
                resource="system",
                result="SUCCESS",
                details="This record should fail and rollback",
            )

    # 3. Verify that the failed record was NOT committed and DB is clean
    with store.connection() as con:
        rows = con.execute("SELECT * FROM admin_audit_log WHERE action = 'FAILED_ACTION'").fetchall()
        assert len(rows) == 0
        total_count = con.execute("SELECT COUNT(*) FROM admin_audit_log").fetchone()[0]
        assert total_count == 1

    # 4. Write a subsequent record and confirm it links to the first record without a gap
    second = store.record_audit(
        username="admin",
        role="ADMIN",
        action="AFTER_FAIL_RECOVERY",
        resource="system",
        result="SUCCESS",
        details="Post-failure recovery record",
    )
    assert second["prev_hash"] == first_hash

    # 5. Verify unbroken chain
    integrity = store.verify_audit_log_integrity()
    assert integrity["valid"] is True
    assert integrity["count"] == 2
