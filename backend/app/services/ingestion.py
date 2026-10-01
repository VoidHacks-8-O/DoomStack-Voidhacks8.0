"""High-throughput streaming ingestion pipeline for ANVITRACE.

Handles:
- Chunked CSV / Parquet reading via Polars
- SHA-256 dataset hash calculation
- Validation and normalization (Sender, Receiver, IFSC, Amounts, Timestamps)
- record_id surrogate key assignment
- Exact duplicate detection vs repeated Transaction_ID tracking
- Bulk write to DuckDB canonical transactions table
- Precomputing basic account-level features
- Building forensic adjacency and temporal indexes
"""

import hashlib
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb
import polars as pl

from app.config.constants import (
    DEFAULT_CHUNK_SIZE,
    NORMALIZATION_VERSION,
    SCHEMA_VERSION,
    STATUS_INVALID,
    STATUS_VALID,
)
from app.database.duckdb import get_connection
from app.database.repositories.dataset import DatasetRepository
from app.indexes.manager import ForensicIndexManager
from app.utils.logging import log_event, logger
from app.utils.validators import (
    validate_account_id,
    validate_amount,
    validate_ifsc,
    validate_payment_mode,
    validate_timestamp,
)


def compute_file_sha256(file_path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Compute deterministic SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()


class IngestionService:
    """Orchestrates streaming ingestion, normalization, storage and indexing."""

    def __init__(self, conn: duckdb.DuckDBPyConnection | None = None):
        self.conn = conn or get_connection()
        self.repo = DatasetRepository(self.conn)

    def ingest_file(
        self,
        file_path: Path,
        dataset_id: str | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> dict[str, Any]:
        """Execute full streaming ingestion workflow for a given CSV file."""
        start_time = datetime.now()
        t0 = time.perf_counter()

        # 1. Compute SHA-256 dataset hash
        logger.info(f"Computing SHA-256 for {file_path.name}...")
        dataset_hash = compute_file_sha256(file_path)

        # 2. Assign deterministic or provided dataset_id
        if not dataset_id:
            dataset_id = f"ds_{dataset_hash[:16]}"

        run_id = f"run_{uuid.uuid4().hex[:12]}"
        log_event(
            "INGESTION_START",
            dataset_id=dataset_id,
            run_id=run_id,
            file=file_path.name,
        )

        # Register dataset in repository
        self.repo.create_dataset(
            dataset_id=dataset_id,
            dataset_hash=dataset_hash,
            filename=file_path.name,
            schema_version=SCHEMA_VERSION,
            normalization_version=NORMALIZATION_VERSION,
        )

        # Clear any partial/previous records for this dataset_id (idempotency)
        self.conn.execute(f"DELETE FROM transactions WHERE dataset_id = '{dataset_id}'")
        self.conn.execute(f"DELETE FROM account_features WHERE dataset_id = '{dataset_id}'")

        # 3. Stream through CSV chunks via Polars
        reader = pl.read_csv_batched(str(file_path), batch_size=chunk_size)

        total_rows = 0
        valid_rows = 0
        invalid_rows = 0
        seen_tx_ids: set[str] = set()
        seen_row_hashes: set[str] = set()
        repeated_tx_count = 0
        exact_duplicate_count = 0

        global_row_idx = 0

        while True:
            batches = reader.next_batches(1)
            if not batches:
                break
            chunk_df = batches[0]
            if chunk_df.is_empty():
                break

            processed_rows: list[dict[str, Any]] = []

            for row in chunk_df.iter_rows(named=True):
                global_row_idx += 1
                total_rows += 1

                tx_id = str(row.get("Transaction_ID") or "").strip()
                sender = str(row.get("Sender_Account") or "").strip()
                receiver = str(row.get("Receiver_Account") or "").strip()
                s_ifsc = str(row.get("Sender_IFSC") or "").strip()
                r_ifsc = str(row.get("Receiver_IFSC") or "").strip()
                raw_amt = row.get("Amount")
                raw_ts = row.get("Timestamp")
                raw_mode = str(row.get("Payment_Mode") or "").strip()
                narration = str(row.get("Narration") or "") if "Narration" in row else None
                ip_addr = str(row.get("IP_Address") or "") if "IP_Address" in row else None
                device = str(row.get("Device_Type") or "UNKNOWN") if "Device_Type" in row else "UNKNOWN"

                # Validation checks
                is_valid = True
                val_errs: list[str] = []

                ok_s, s_clean = validate_account_id(sender)
                if not ok_s:
                    is_valid = False
                    val_errs.append(s_clean)

                ok_r, r_clean = validate_account_id(receiver)
                if not ok_r:
                    is_valid = False
                    val_errs.append(r_clean)

                ok_s_ifsc, s_ifsc_clean = validate_ifsc(s_ifsc)
                if not ok_s_ifsc:
                    is_valid = False
                    val_errs.append(s_ifsc_clean)

                ok_r_ifsc, r_ifsc_clean = validate_ifsc(r_ifsc)
                if not ok_r_ifsc:
                    is_valid = False
                    val_errs.append(r_ifsc_clean)

                ok_amt, amt_val, amt_err = validate_amount(raw_amt)
                if not ok_amt:
                    is_valid = False
                    val_errs.append(amt_err)

                ok_ts, ts_clean = validate_timestamp(raw_ts)
                if not ok_ts:
                    is_valid = False
                    val_errs.append(ts_clean)

                ok_mode, mode_clean = validate_payment_mode(raw_mode)
                if not ok_mode:
                    is_valid = False
                    val_errs.append(mode_clean)

                if is_valid:
                    valid_rows += 1
                    status_flag = STATUS_VALID
                else:
                    invalid_rows += 1
                    status_flag = STATUS_INVALID

                # Repeated Transaction_ID check
                is_repeated = False
                if tx_id in seen_tx_ids:
                    is_repeated = True
                    repeated_tx_count += 1
                else:
                    seen_tx_ids.add(tx_id)

                # Exact duplicate detection across all source fields
                row_fingerprint = f"{tx_id}|{sender}|{receiver}|{s_ifsc}|{r_ifsc}|{amt_val}|{ts_clean}|{mode_clean}"
                is_exact_dup = False
                if row_fingerprint in seen_row_hashes:
                    is_exact_dup = True
                    exact_duplicate_count += 1
                else:
                    seen_row_hashes.add(row_fingerprint)

                # Surrogate primary key: record_id
                record_id = f"rec_{dataset_id}_{global_row_idx}"

                processed_rows.append(
                    {
                        "record_id": record_id,
                        "Transaction_ID": tx_id,
                        "Sender_Account": s_clean if ok_s else sender,
                        "Receiver_Account": r_clean if ok_r else receiver,
                        "Sender_IFSC": s_ifsc_clean if ok_s_ifsc else s_ifsc,
                        "Receiver_IFSC": r_ifsc_clean if ok_r_ifsc else r_ifsc,
                        "Amount": amt_val,
                        "Timestamp": ts_clean if ok_ts else "1970-01-01 00:00:00",
                        "Payment_Mode": mode_clean if ok_mode else raw_mode,
                        "Narration": narration,
                        "IP_Address": ip_addr,
                        "Device_Type": device,
                        "dataset_id": dataset_id,
                        "source_row": global_row_idx,
                        "validation_status": status_flag,
                        "is_repeated_tx": is_repeated,
                        "is_exact_duplicate": is_exact_dup,
                    }
                )

            # Insert batch into DuckDB
            if processed_rows:
                batch_pl = pl.DataFrame(processed_rows)
                # Cast Timestamp & Amount to proper Arrow types for DuckDB insertion
                batch_arrow = batch_pl.to_arrow()
                self.conn.register("batch_chunk", batch_arrow)
                self.conn.execute(
                    """
                    INSERT INTO transactions (
                        record_id, Transaction_ID, Sender_Account, Receiver_Account,
                        Sender_IFSC, Receiver_IFSC, Amount, Timestamp,
                        Payment_Mode, Narration, IP_Address, Device_Type,
                        dataset_id, source_row, validation_status,
                        is_repeated_tx, is_exact_duplicate
                    )
                    SELECT
                        record_id, Transaction_ID, Sender_Account, Receiver_Account,
                        Sender_IFSC, Receiver_IFSC, CAST(Amount AS DECIMAL(18, 2)),
                        CAST(Timestamp AS TIMESTAMP), Payment_Mode, Narration,
                        IP_Address, Device_Type, dataset_id, source_row,
                        validation_status, is_repeated_tx, is_exact_duplicate
                    FROM batch_chunk
                    """
                )
                self.conn.unregister("batch_chunk")

            logger.info(f"Processed {total_rows:,} rows...")

        # 4. Precompute basic account-level features
        logger.info(f"Precomputing account features for dataset {dataset_id}...")
        self._precompute_account_features(dataset_id)

        # 5. Build forensic adjacency and temporal indexes
        index_manager = ForensicIndexManager(dataset_id)
        index_paths = index_manager.build_indexes(self.conn)

        # 6. Finalize metrics & run record
        t1 = time.perf_counter()
        end_time = datetime.now()
        duration = round(t1 - t0, 3)
        rps = round(total_rows / duration, 1) if duration > 0 else float(total_rows)

        self.repo.update_dataset_metrics(
            dataset_id=dataset_id,
            total_rows=total_rows,
            valid_rows=valid_rows,
            invalid_rows=invalid_rows,
            repeated_tx_ids=repeated_tx_count,
            exact_duplicates=exact_duplicate_count,
            status="COMPLETED",
        )

        self.repo.record_ingestion_run(
            run_id=run_id,
            dataset_id=dataset_id,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            rows_per_second=rps,
            status="SUCCESS",
        )

        log_event(
            "INGESTION_COMPLETED",
            dataset_id=dataset_id,
            total_rows=total_rows,
            valid=valid_rows,
            invalid=invalid_rows,
            duration_seconds=duration,
            rows_per_sec=rps,
        )

        return {
            "dataset_id": dataset_id,
            "dataset_hash": dataset_hash,
            "filename": file_path.name,
            "total_rows": total_rows,
            "valid_rows": valid_rows,
            "invalid_rows": invalid_rows,
            "repeated_tx_ids": repeated_tx_count,
            "exact_duplicates": exact_duplicate_count,
            "duration_seconds": duration,
            "rows_per_second": rps,
            "indexes": index_paths,
            "status": "COMPLETED",
        }

    def _precompute_account_features(self, dataset_id: str) -> None:
        """Precompute incoming/outgoing counts and volumes per account into account_features table."""
        self.conn.execute(
            f"""
            INSERT INTO account_features (
                account_id, dataset_id, in_tx_count, out_tx_count,
                in_amount, out_amount, distinct_senders, distinct_receivers,
                first_tx_timestamp, last_tx_timestamp
            )
            WITH all_accounts AS (
                SELECT Sender_Account AS account_id FROM transactions WHERE dataset_id = '{dataset_id}'
                UNION
                SELECT Receiver_Account AS account_id FROM transactions WHERE dataset_id = '{dataset_id}'
            ),
            outgoing AS (
                SELECT
                    Sender_Account AS account_id,
                    COUNT(*) AS out_tx_count,
                    COALESCE(SUM(Amount), 0.00) AS out_amount,
                    COUNT(DISTINCT Receiver_Account) AS distinct_receivers,
                    MIN(Timestamp) AS min_out_ts,
                    MAX(Timestamp) AS max_out_ts
                FROM transactions
                WHERE dataset_id = '{dataset_id}'
                GROUP BY Sender_Account
            ),
            incoming AS (
                SELECT
                    Receiver_Account AS account_id,
                    COUNT(*) AS in_tx_count,
                    COALESCE(SUM(Amount), 0.00) AS in_amount,
                    COUNT(DISTINCT Sender_Account) AS distinct_senders,
                    MIN(Timestamp) AS min_in_ts,
                    MAX(Timestamp) AS max_in_ts
                FROM transactions
                WHERE dataset_id = '{dataset_id}'
                GROUP BY Receiver_Account
            )
            SELECT
                a.account_id,
                '{dataset_id}' AS dataset_id,
                COALESCE(i.in_tx_count, 0) AS in_tx_count,
                COALESCE(o.out_tx_count, 0) AS out_tx_count,
                CAST(COALESCE(i.in_amount, 0.00) AS DECIMAL(18, 2)) AS in_amount,
                CAST(COALESCE(o.out_amount, 0.00) AS DECIMAL(18, 2)) AS out_amount,
                COALESCE(i.distinct_senders, 0) AS distinct_senders,
                COALESCE(o.distinct_receivers, 0) AS distinct_receivers,
                LEAST(COALESCE(o.min_out_ts, i.min_in_ts), COALESCE(i.min_in_ts, o.min_out_ts)) AS first_tx_timestamp,
                GREATEST(COALESCE(o.max_out_ts, i.max_in_ts), COALESCE(i.max_in_ts, o.max_out_ts)) AS last_tx_timestamp
            FROM all_accounts a
            LEFT JOIN outgoing o ON a.account_id = o.account_id
            LEFT JOIN incoming i ON a.account_id = i.account_id
            ON CONFLICT (account_id, dataset_id) DO UPDATE SET
                in_tx_count = EXCLUDED.in_tx_count,
                out_tx_count = EXCLUDED.out_tx_count,
                in_amount = EXCLUDED.in_amount,
                out_amount = EXCLUDED.out_amount,
                distinct_senders = EXCLUDED.distinct_senders,
                distinct_receivers = EXCLUDED.distinct_receivers,
                first_tx_timestamp = EXCLUDED.first_tx_timestamp,
                last_tx_timestamp = EXCLUDED.last_tx_timestamp;
            """
        )
