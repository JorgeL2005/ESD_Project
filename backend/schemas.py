from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class RegisterRequest(BaseModel):
    username: str
    role: Optional[str] = Field(default="voter")
    password: str


class RegisterResponse(BaseModel):
    message: str
    private_key_pem: str
    username: str
    role: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class VoteRequest(BaseModel):
    encrypted_vote_b64: str
    signature_b64: str


class VoteLedgerItem(BaseModel):
    id: int
    vote_hash_hex: str
    prev_hash_hex: Optional[str]
    timestamp: datetime
    nonce: Optional[int] = None
    pow_hash_hex: Optional[str] = None


class LedgerPage(BaseModel):
    items: List[VoteLedgerItem]
    page: int
    page_size: int
    total: int


class AuditLogItem(BaseModel):
    id: int
    username: Optional[str]
    action: str
    ip: Optional[str]
    timestamp: datetime


class AuditLogPage(BaseModel):
    items: List[AuditLogItem]
    page: int
    page_size: int
    total: int


class SQLQuery(BaseModel):
    query: str


class SQLResult(BaseModel):
    columns: List[str]
    rows: List[List[str | int | float | None]]
    


class VoteStatItem(BaseModel):
    candidate: str
    votes: int
    percentage: float


class VoteStats(BaseModel):
    total: int
    results: List[VoteStatItem]
class CandidateOption(BaseModel):
    id: int
    name: str

class VotePlainRequest(BaseModel):
    candidate_id: int

class ResultSummaryItem(BaseModel):
    candidate: str
    vote_count: int
    percentage: float

class ResultSummaryResponse(BaseModel):
    total_votes: int
    results: List[ResultSummaryItem]

class BallotIssueResponse(BaseModel):
    ballot_token: str
    jti: str
    expires_at: datetime
