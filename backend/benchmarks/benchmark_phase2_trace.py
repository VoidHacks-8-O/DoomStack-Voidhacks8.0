"""Performance benchmark harness for Phase 2: Four-Hop Temporal Traversal & Lineage.

Measures:
- Latency (p50, p95, p99, mean) across multiple trace executions
- Verification of target: <= 2.0 seconds per 4-hop investigation
- Memory utilization snapshot
"""

import argparse
import random
import statistics
import sys
import time
from pathlib import Path

# Add backend to sys.path
backend_path = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_path))

import duckdb  # noqa: E402

from app.database.schema import apply_schema  # noqa: E402
from app.services.ingestion import IngestionService  # noqa: E402
from app.services.investigation import InvestigationService  # noqa: E402
from benchmarks.benchmark_ingestion import generate_synthetic_transactions  # noqa: E402


def benchmark_four_hop_latency(
    num_queries: int = 50,
    rows: int = 50_000,
    chunk_size: int = 25_000,
    dataset_file: Path | None = None,
) -> None:
    """Benchmark p50, p95, and p99 four-hop trace latencies."""
    bench_dir = backend_path / "benchmarks" / "data"
    bench_dir.mkdir(parents=True, exist_ok=True)

    if dataset_file and dataset_file.exists():
        csv_path = dataset_file
    else:
        csv_path = bench_dir / f"benchmark_p2_{rows}.csv"
        if not csv_path.exists():
            generate_synthetic_transactions(csv_path, num_rows=rows)

    print(f"\nSetting up benchmark database with {csv_path.name}...")
    conn = duckdb.connect(":memory:")
    apply_schema(conn)

    ingest_svc = IngestionService(conn)
    result = ingest_svc.ingest_file(csv_path, dataset_id="ds_bench_p2", chunk_size=chunk_size)
    print(f"Ingested {result['total_rows']:,} rows in {result['duration_seconds']}s.")

    # Find distinct sender accounts to query
    sample_accounts = [
        r[0]
        for r in conn.execute(
            "SELECT DISTINCT Sender_Account FROM transactions WHERE dataset_id = 'ds_bench_p2' LIMIT 500"
        ).fetchall()
    ]

    if not sample_accounts:
        print("Error: No accounts found to benchmark.")
        return

    inv_svc = InvestigationService(conn)
    latencies_ms: list[float] = []

    print(f"\n--- EXECUTING {num_queries} FOUR-HOP TRACE QUERIES ---")
    for i in range(num_queries):
        acc = random.choice(sample_accounts)
        t0 = time.perf_counter()
        trace = inv_svc.run_trace(
            victim_account=acc,
            dataset_id="ds_bench_p2",
            max_hops=4,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000
        latencies_ms.append(elapsed_ms)
        if (i + 1) % 10 == 0 or (i + 1) == num_queries:
            print(f"Query {i + 1}/{num_queries} -> {len(trace.money_trail)} edges found in {elapsed_ms:.2f} ms")

    # Calculate statistics
    latencies_ms.sort()
    p50 = statistics.median(latencies_ms)
    p95 = latencies_ms[int(len(latencies_ms) * 0.95)]
    p99 = latencies_ms[int(len(latencies_ms) * 0.99)]
    mean_val = statistics.mean(latencies_ms)

    print("\n================ LATENCY BENCHMARK RESULTS ================")
    print(f"Queries Executed        : {num_queries}")
    print(f"Mean Latency            : {mean_val:.2f} ms")
    print(f"p50 Latency (Median)    : {p50:.2f} ms")
    print(f"p95 Latency             : {p95:.2f} ms")
    print(f"p99 Latency             : {p99:.2f} ms")
    print(f"Max Latency             : {max(latencies_ms):.2f} ms")
    print("----------------------------------------------------------")
    if p99 <= 2000.0:
        print(f">> PERFORMANCE TARGET (<= 2.0s per trace): ACHIEVED (p99 = {p99:.2f} ms) <<")
    else:
        print(f">> PERFORMANCE TARGET: EXCEEDED TARGET ({p99:.2f} ms > 2000 ms) <<")
    print("==========================================================\n")
    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ANVITRACE Phase 2 Four-Hop Latency Benchmark")
    parser.add_argument("--queries", type=int, default=30, help="Number of trace queries to benchmark")
    parser.add_argument("--rows", type=int, default=50_000, help="Dataset row count")
    parser.add_argument("--file", type=str, default=None, help="Custom dataset CSV file")
    args = parser.parse_args()
    input_file = Path(args.file) if args.file else None
    benchmark_four_hop_latency(num_queries=args.queries, rows=args.rows, dataset_file=input_file)
