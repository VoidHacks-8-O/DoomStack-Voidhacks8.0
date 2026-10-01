"""Investigation schemas for forensic multi-hop traces and amount lineage."""

from typing import Any

from pydantic import BaseModel, Field

from app.schemas.graph import MoneyTrailEdge, MoneyTrailGraph


class InvestigationParameters(BaseModel):
    """Configuration parameters for deterministic temporal trace."""

    max_hops: int = Field(default=4, ge=1, le=4, description="Bounded maximum depth (1..4)")
    time_window_hours: float | None = Field(
        default=None,
        description="Optional maximum chronological window forward from victim transaction in hours",
    )
    min_amount: float | None = Field(
        default=None,
        description="Optional minimum transaction amount filter",
    )
    rule_version: str = "2.0.0"


class InvestigationTraceResponse(BaseModel):
    """Full forensic investigation trace result."""

    investigation_id: str
    dataset_id: str
    victim_account: str
    victim_transaction: dict[str, Any] | None = None
    parameters: InvestigationParameters
    money_trail: list[MoneyTrailEdge] = Field(default_factory=list)
    graph: MoneyTrailGraph | None = None
    execution_time_ms: float = 0.0

    # Placeholders for later phases (as specified in Phase 2 architecture)
    layer_candidates: list[dict[str, Any]] = Field(default_factory=list)
    risk_summary: dict[str, Any] = Field(default_factory=dict)
    recovery_summary: dict[str, Any] = Field(default_factory=dict)
    shared_infrastructure: dict[str, Any] = Field(default_factory=dict)
    evidence_metadata: dict[str, Any] = Field(default_factory=dict)
