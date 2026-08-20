from typing import Any, Literal

from pydantic import BaseModel, Field

from app.domain.ioc.types import IocType, ParsedIoc

Severity = Literal["unknown", "low", "medium", "high", "critical"]


class InvestigationRequest(BaseModel):
    ioc: str = Field(min_length=1, max_length=4096)


class RiskSummary(BaseModel):
    score: int = Field(ge=0, le=100)
    severity: Severity


class McpObservation(BaseModel):
    source: str
    raw: dict[str, Any]
    reputation: dict[str, Any] = Field(default_factory=dict)
    geolocation: dict[str, Any] | None = None
    relationships: list[dict[str, Any]] = Field(default_factory=list)
    community_reports: list[dict[str, Any]] = Field(default_factory=list)


class ResultModules(BaseModel):
    reputation: dict[str, Any] = Field(default_factory=dict)
    geolocation: dict[str, Any] = Field(default_factory=dict)
    relationship_graph: dict[str, Any] = Field(default_factory=dict)
    community_reports: list[dict[str, Any]] = Field(default_factory=list)


class TacticalMappings(BaseModel):
    mitre_attack: list[dict[str, str]] = Field(default_factory=list)
    nist: list[dict[str, str]] = Field(default_factory=list)
    iso: list[dict[str, str]] = Field(default_factory=list)


class InvestigationResponse(BaseModel):
    ioc: ParsedIoc
    risk: RiskSummary
    modules: ResultModules
    mappings: TacticalMappings
    playbooks: list[dict[str, Any]] = Field(default_factory=list)
    sources: list[str]
    mcp_servers_queried: list[str]
    used_byok: bool = False
    quota: dict[str, int | str | bool] = Field(default_factory=dict)


class ProviderPlan(BaseModel):
    ioc_type: IocType
    providers: list[str]
