"""Application-wide constants."""

# --- Dataset source columns (as received) ---
SOURCE_COLUMNS: list[str] = [
    "Transaction_ID",
    "Timestamp",
    "Sender_Account",
    "Sender_Name",
    "Sender_IFSC",
    "Receiver_Account",
    "Receiver_Name",
    "Receiver_IFSC",
    "Amount",
    "Payment_Mode",
    "Status",
]

# --- Internal identifier added during ingestion ---
RECORD_ID_COLUMN: str = "record_id"

# --- Payment modes ---
PAYMENT_MODES: list[str] = ["UPI", "IMPS", "NEFT", "RTGS"]

# --- Account identifier length ---
ACCOUNT_ID_LENGTH: int = 12

# --- IFSC length ---
IFSC_LENGTH: int = 11
