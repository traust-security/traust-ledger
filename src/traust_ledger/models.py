from __future__ import annotations

from pydantic import BaseModel, Field

from traust_ledger.api.findings import FindingDisposition, FindingsSummary
from traust_ledger.constants.domain import PRODUCT_REPO_ID_PATTERN


class InitializeRequest(BaseModel):
    product_repo_id: str | None = Field(..., pattern=PRODUCT_REPO_ID_PATTERN)
    layer: dict


class EventEnvelope(BaseModel):
    kind: str
    event: dict[str, object]


class SubmitResponse(BaseModel):
    id: str
    status: str
    event_count: int | None = None
    merkle_root: str | None = None
    event_ids: list[str] = []
    queue_added: int = 0


class RestatementRequest(BaseModel):
    restatement: dict[str, object]
    rationale: str
    recorded_at: str | None = None
    finding_ref: str | None = None


class RestatementResponse(BaseModel):
    event_id: str
    layer_id: str
    target: str
    merkle_root: str | None = None


class VerifyFinding(BaseModel):
    severity: str
    message: str


class VerifyResponse(BaseModel):
    passed: bool
    findings: list[VerifyFinding] = []
    checked_at: str


class FindingsResponse(BaseModel):
    findings: list[FindingDisposition]
    summary: FindingsSummary
    ledger_only: bool = True


class LayerFindings(BaseModel):
    layer_id: str
    merkle_root: str | None = None
    merkle_epoch: int | None = None
    findings: list[FindingDisposition]
    summary: FindingsSummary
    ledger_only: bool = True


class BulkFindingsResponse(BaseModel):
    layers: list[LayerFindings]
    total_findings: int
    next_cursor: str | None = None
    has_more: bool = False


class EventsResponse(BaseModel):
    events: list[dict[str, object]]
    total: int
    layer_id: str


class ResolveResponse(BaseModel):
    resolved: bool
    key: str


class BatchSubmitRequest(BaseModel):
    source_ref: str
    recorded_at: str
    events: list[dict[str, object]] = []
    needs_review: list[dict[str, object]] = []


class FingerprintRequest(BaseModel):
    findings: list[dict[str, object]]
    repository: str | None = None


class FingerprintResponse(BaseModel):
    findings: list[dict[str, object]]
    stamped_count: int


class LayerRef(BaseModel):
    layer_id: str
    product_repo_id: str | None = None


class LayerListResponse(BaseModel):
    layers: list[LayerRef]


class StampRequest(BaseModel):
    fingerprints: dict[str, str]


class StampResponse(BaseModel):
    merkle_root: str | None = None
    layer_id: str
    stamped: int
