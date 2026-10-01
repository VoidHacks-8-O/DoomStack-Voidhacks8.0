"""Deterministic test suite for Phase 2: Temporal Graph Traversal & Amount Lineage.

Verifies:
1. branching graph (one-to-many amount split)
2. cycle detection (path-aware without infinite loop)
3. repeated account through alternative paths
4. out-of-order transactions (temporal filter exclusion)
5. exactly 3 hops
6. exactly 4 hops
7. attempted fifth hop (must be strictly rejected/not traversed)
8. temporal exclusion (t_out < t_in rejected)
9. one-to-many amount split (₹10,000 -> ₹6,000 + ₹4,000)
10. many-to-one convergence
11. partial attribution
12. double-count prevention across converging paths
13. repeated Transaction_ID with different record_ids
14. deterministic repeated query results
15. account profile and timeline API endpoints
"""

from pathlib import Path

import duckdb
import pytest
from fastapi.testclient import TestClient

from app.database.schema import apply_schema
from app.main import app
from app.services.ingestion import IngestionService
from app.services.investigation import InvestigationService


@pytest.fixture
def phase2_db():
    """Create in-memory DuckDB initialized with canonical schema."""
    conn = duckdb.connect(":memory:")
    apply_schema(conn)
    yield conn
    conn.close()


@pytest.fixture
def forensic_graph_csv(tmp_path: Path):
    """Generate a multi-hop forensic scenario dataset testing splits, cycles, and 5-hop bounds.

    Scenario:
    - Victim: ACC_VICTIM_01 sends ₹10,000 to ACC_MULE_A01 (Hop 1) at 10:00:00
    - Split: ACC_MULE_A01 sends ₹6,000 to ACC_MULE_B01 and ₹4,000 to ACC_MULE_B02 (Hop 2) at 10:10:00 & 10:15:00
    - Out-of-order / Temporal invalid: ACC_MULE_A01 had sent ₹2,000 to ACC_IGNORED at 09:00:00 (before victim tx) -> MUST BE EXCLUDED
    - Convergence: ACC_MULE_B01 sends ₹5,000 to ACC_MULE_C01 (Hop 3) at 10:20:00
                   ACC_MULE_B02 sends ₹3,000 to ACC_MULE_C01 (Hop 3) at 10:25:00
    - 4th Hop: ACC_MULE_C01 sends ₹7,000 to ACC_MULE_D01 (Hop 4) at 10:30:00
    - 5th Hop Attempt: ACC_MULE_D01 sends ₹5,000 to ACC_MULE_E01 (Hop 5) at 10:40:00 -> MUST BE REJECTED/NOT TRAVERSED
    - Cycle: ACC_MULE_B01 sends ₹500 back to ACC_VICTIM_01 at 10:22:00 -> MUST BE FLAGGED AS CYCLE, BOUNDED
    - Repeated Transaction_ID: TX_SHARED_01 appears on two distinct transactions
    """
    csv_file = tmp_path / "phase2_scenario.csv"
    rows = [
        # Hop 1: Victim -> Mule A (₹10,000)
        "TX_VIC_001,2026-03-01 10:00:00,ACC_VICTIM_01,Victim,SBIN0001001,ACC_MULE_A01,MuleA,HDFC0002001,10000.00,UPI,SUCCESS",
        # Prior tx from Mule A before victim funds arrived -> MUST BE EXCLUDED by temporal rule
        "TX_PRIOR_01,2026-03-01 09:00:00,ACC_MULE_A01,MuleA,HDFC0002001,ACC_IGNORED_1,Ignored,ICIC0003001,2000.00,UPI,SUCCESS",
        # Hop 2 Split: Mule A -> Mule B1 (₹6,000) & Mule A -> Mule B2 (₹4,000)
        "TX_SPLIT_01,2026-03-01 10:10:00,ACC_MULE_A01,MuleA,HDFC0002001,ACC_MULE_B01,MuleB1,PUNB0004001,6000.00,IMPS,SUCCESS",
        "TX_SPLIT_02,2026-03-01 10:15:00,ACC_MULE_A01,MuleA,HDFC0002001,ACC_MULE_B02,MuleB2,BARB0005001,4000.00,IMPS,SUCCESS",
        # Cycle attempt: Mule B1 sends ₹500 back to Victim at 10:22:00
        "TX_CYCLE_01,2026-03-01 10:22:00,ACC_MULE_B01,MuleB1,PUNB0004001,ACC_VICTIM_01,Victim,SBIN0001001,500.00,UPI,SUCCESS",
        # Hop 3 Convergence: Mule B1 -> Mule C1 (₹5,000) & Mule B2 -> Mule C1 (₹3,000)
        "TX_SHARED_01,2026-03-01 10:20:00,ACC_MULE_B01,MuleB1,PUNB0004001,ACC_MULE_C01,MuleC1,KKBK0006001,5000.00,NEFT,SUCCESS",
        "TX_CONV_02,2026-03-01 10:25:00,ACC_MULE_B02,MuleB2,BARB0005001,ACC_MULE_C01,MuleC1,KKBK0006001,3000.00,NEFT,SUCCESS",
        # Hop 4: Mule C1 -> Mule D1 (₹7,000) - Shared Transaction_ID with different record_id
        "TX_SHARED_01,2026-03-01 10:30:00,ACC_MULE_C01,MuleC1,KKBK0006001,ACC_MULE_D01,MuleD1,AXIS0007001,7000.00,RTGS,SUCCESS",
        # Hop 5 Attempt: Mule D1 -> Mule E1 (₹5,000) -> MUST NOT BE TRAVERSED (Hard limit = 4)
        "TX_HOP5_01,2026-03-01 10:40:00,ACC_MULE_D01,MuleD1,AXIS0007001,ACC_MULE_E01,MuleE1,YESB0008001,5000.00,RTGS,SUCCESS",
    ]
    header = "Transaction_ID,Timestamp,Sender_Account,Sender_Name,Sender_IFSC,Receiver_Account,Receiver_Name,Receiver_IFSC,Amount,Payment_Mode,Status\n"
    csv_file.write_text(header + "\n".join(rows) + "\n", encoding="utf-8")
    return csv_file


def test_four_hop_strict_bounding(phase2_db, forensic_graph_csv):
    """Verify that traversal halts strictly at max_hops=4 and never expands to hop 5."""
    ingest_svc = IngestionService(phase2_db)
    ingest_svc.ingest_file(forensic_graph_csv, dataset_id="ds_p2_test")

    inv_svc = InvestigationService(phase2_db)
    trace = inv_svc.run_trace(
        victim_account="ACC_VICTIM_01",
        dataset_id="ds_p2_test",
        max_hops=4,
    )

    hops = [e.hop for e in trace.money_trail]
    assert 1 in hops
    assert 2 in hops
    assert 3 in hops
    assert 4 in hops
    assert 5 not in hops, "Attempted fifth hop was not rejected/bounded!"

    # Verify Hop 5 target account ACC_MULE_E01 never appears as to_account in the money trail
    dest_accounts = [e.to_account for e in trace.money_trail]
    assert "ACC_MULE_E01" not in dest_accounts


def test_exact_hop_bounds(phase2_db, forensic_graph_csv):
    """Verify exact 1, 2, and 3 hop limits when configured."""
    ingest_svc = IngestionService(phase2_db)
    ingest_svc.ingest_file(forensic_graph_csv, dataset_id="ds_p2_test")
    inv_svc = InvestigationService(phase2_db)

    # Exactly 1 hop
    trace_1 = inv_svc.run_trace(victim_account="ACC_VICTIM_01", dataset_id="ds_p2_test", max_hops=1)
    assert all(e.hop == 1 for e in trace_1.money_trail)

    # Exactly 2 hops
    trace_2 = inv_svc.run_trace(victim_account="ACC_VICTIM_01", dataset_id="ds_p2_test", max_hops=2)
    assert max(e.hop for e in trace_2.money_trail) == 2

    # Exactly 3 hops
    trace_3 = inv_svc.run_trace(victim_account="ACC_VICTIM_01", dataset_id="ds_p2_test", max_hops=3)
    assert max(e.hop for e in trace_3.money_trail) == 3


def test_temporal_exclusion(phase2_db, forensic_graph_csv):
    """Verify transactions preceding the victim transaction are excluded."""
    ingest_svc = IngestionService(phase2_db)
    ingest_svc.ingest_file(forensic_graph_csv, dataset_id="ds_p2_test")

    inv_svc = InvestigationService(phase2_db)
    trace = inv_svc.run_trace(victim_account="ACC_VICTIM_01", dataset_id="ds_p2_test")

    # TX_PRIOR_01 was at 09:00:00 (before victim tx at 10:00:00)
    tx_ids = [e.Transaction_ID for e in trace.money_trail]
    assert "TX_PRIOR_01" not in tx_ids
    assert "ACC_IGNORED_1" not in [e.to_account for e in trace.money_trail]


def test_cycle_detection(phase2_db, forensic_graph_csv):
    """Verify cycles are flagged and do not cause infinite recursion."""
    ingest_svc = IngestionService(phase2_db)
    ingest_svc.ingest_file(forensic_graph_csv, dataset_id="ds_p2_test")

    inv_svc = InvestigationService(phase2_db)
    trace = inv_svc.run_trace(victim_account="ACC_VICTIM_01", dataset_id="ds_p2_test")

    # TX_CYCLE_01 loops back from Mule B1 to Victim
    cycle_edges = [e for e in trace.money_trail if e.is_cycle]
    assert len(cycle_edges) == 1
    assert cycle_edges[0].to_account == "ACC_VICTIM_01"
    assert cycle_edges[0].attributable_amount == 0.0
    assert cycle_edges[0].lineage_status == "unresolved"


def test_amount_lineage_split_and_double_count_prevention(phase2_db, forensic_graph_csv):
    """Verify amount lineage: one-to-many split and convergence without double-counting."""
    ingest_svc = IngestionService(phase2_db)
    ingest_svc.ingest_file(forensic_graph_csv, dataset_id="ds_p2_test")

    inv_svc = InvestigationService(phase2_db)
    trace = inv_svc.run_trace(victim_account="ACC_VICTIM_01", dataset_id="ds_p2_test")

    # Hop 1: Victim ₹10,000 -> traced
    h1 = [e for e in trace.money_trail if e.hop == 1]
    assert len(h1) == 1
    assert h1[0].attributable_amount == 10000.00
    assert h1[0].lineage_status == "traced"

    # Hop 2: Split ₹6,000 + ₹4,000 = ₹10,000 total available
    h2 = [e for e in trace.money_trail if e.hop == 2]
    h2_attributed = sum(e.attributable_amount for e in h2 if not e.is_cycle)
    assert h2_attributed == 10000.00
    assert all(e.lineage_status == "attributed" for e in h2 if not e.is_cycle)

    # Hop 3: Mule B1 (avail 6000) sends 5000 -> attr 5000. Mule B2 (avail 4000) sends 3000 -> attr 3000.
    h3 = [e for e in trace.money_trail if e.hop == 3]
    h3_attributed = sum(e.attributable_amount for e in h3)
    assert h3_attributed == 8000.00  # 5000 + 3000 <= 10000

    # Hop 4: Mule C1 receives 5000 + 3000 = 8000 attributable. Sends 7000 to D1.
    h4 = [e for e in trace.money_trail if e.hop == 4]
    assert len(h4) == 1
    assert h4[0].attributable_amount == 7000.00
    assert h4[0].lineage_status == "attributed"

    # Verify no edge exceeds the initial ₹10,000 victim amount
    for e in trace.money_trail:
        assert e.attributable_amount <= 10000.00


def test_repeated_transaction_id_preservation(phase2_db, forensic_graph_csv):
    """Verify that repeated Transaction_ID (TX_SHARED_01) maintains distinct record_ids."""
    ingest_svc = IngestionService(phase2_db)
    ingest_svc.ingest_file(forensic_graph_csv, dataset_id="ds_p2_test")

    inv_svc = InvestigationService(phase2_db)
    trace = inv_svc.run_trace(victim_account="ACC_VICTIM_01", dataset_id="ds_p2_test")

    shared_edges = [e for e in trace.money_trail if e.Transaction_ID == "TX_SHARED_01"]
    assert len(shared_edges) == 2
    # Distinct physical record_ids
    assert shared_edges[0].record_id != shared_edges[1].record_id
    # Distinct hops (one is Hop 3, one is Hop 4)
    assert {shared_edges[0].hop, shared_edges[1].hop} == {3, 4}


def test_deterministic_repeated_queries(phase2_db, forensic_graph_csv):
    """Verify trace returns strictly identical results over multiple repeated runs."""
    ingest_svc = IngestionService(phase2_db)
    ingest_svc.ingest_file(forensic_graph_csv, dataset_id="ds_p2_test")

    inv_svc = InvestigationService(phase2_db)
    trace_a = inv_svc.run_trace(victim_account="ACC_VICTIM_01", dataset_id="ds_p2_test")
    trace_b = inv_svc.run_trace(victim_account="ACC_VICTIM_01", dataset_id="ds_p2_test")

    assert len(trace_a.money_trail) == len(trace_b.money_trail)
    for ea, eb in zip(trace_a.money_trail, trace_b.money_trail, strict=True):
        assert ea.record_id == eb.record_id
        assert ea.hop == eb.hop
        assert ea.attributable_amount == eb.attributable_amount
        assert ea.lineage_status == eb.lineage_status


def test_phase2_api_endpoints(forensic_graph_csv):
    """Verify GET /api/accounts/{id}, GET /api/accounts/{id}/transactions, and GET /api/investigations/trace/{id}."""
    client = TestClient(app)

    # Ingest through the API to populate the active DuckDB instance
    with open(forensic_graph_csv, "rb") as f:
        res_upload = client.post("/api/dataset/upload", files={"file": ("p2_scenario.csv", f, "text/csv")})
    assert res_upload.status_code == 202
    ds_id = res_upload.json()["dataset_id"]

    # 1. Account profile
    res_acc = client.get(f"/api/accounts/ACC_VICTIM_01?dataset_id={ds_id}")
    assert res_acc.status_code == 200
    acc_data = res_acc.json()
    assert acc_data["account_id"] == "ACC_VICTIM_01"
    assert acc_data["out_amount"] == 10000.00

    # 2. Account transactions timeline
    res_txs = client.get(f"/api/accounts/ACC_MULE_A01/transactions?dataset_id={ds_id}")
    assert res_txs.status_code == 200
    txs_data = res_txs.json()
    assert txs_data["total_transactions"] >= 3
    # Verify chronological ordering
    ts_list = [t["timestamp"] for t in txs_data["transactions"]]
    assert ts_list == sorted(ts_list)

    # 3. Investigation trace API
    res_trace = client.get(f"/api/investigations/trace/ACC_VICTIM_01?dataset_id={ds_id}&max_hops=4")
    assert res_trace.status_code == 200
    trace_data = res_trace.json()
    assert trace_data["victim_account"] == "ACC_VICTIM_01"
    assert len(trace_data["money_trail"]) > 0
    assert trace_data["parameters"]["max_hops"] == 4
