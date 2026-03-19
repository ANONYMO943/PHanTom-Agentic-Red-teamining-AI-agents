"""
Pydantic models for strict validation of all LLM responses and data structures.
Ensures no silent coercion — invalid fields raise ValidationError.
"""
from pydantic import BaseModel, Field, field_validator
from typing import Literal, Optional, List


class OrchestratorPlan(BaseModel):
    """Validated response from orchestrator's _plan() LLM call."""
    action: Literal["run_agent", "done"]
    agent: Optional[str] = None
    reasoning: str = ""
    reason: str = ""

    @field_validator("agent")
    @classmethod
    def valid_agent(cls, v, info):
        valid_agents = ["recon", "threat_model", "exploit_engine", "patch_agent"]
        if info.data.get("action") == "run_agent":
            if v not in valid_agents:
                raise ValueError(f"Invalid agent '{v}'. Must be one of: {valid_agents}")
        return v


class ExploitAssessment(BaseModel):
    """Validated response from exploit engine's exploitability assessment."""
    is_exploitable: bool = False
    confidence: float = Field(default=0.3, ge=0.0, le=1.0)
    reasoning: str = "Analysis incomplete"
    attack_vector: str = "unknown"
    technique_id: str = "T0000"
    cvss_estimate: float = Field(default=0.0, ge=0.0, le=10.0)
    pivot_suggestion: str = ""


class PivotAssessment(BaseModel):
    """Validated response from exploit engine's pivot re-assessment."""
    is_exploitable: bool = False
    confidence: float = Field(default=0.3, ge=0.0, le=1.0)
    reasoning: str = "Pivot analysis incomplete"
    attack_vector: str = "unknown"
    technique_id: str = "T0000"
    cvss_estimate: float = Field(default=0.0, ge=0.0, le=10.0)
    pivot_applied: str = ""


class PortInfo(BaseModel):
    """Structured port scan result."""
    port: int
    service: str = "unknown"
    version: str = ""
    product: str = ""
    state: str = "open"


class ThreatFinding(BaseModel):
    """A single threat model finding with ATT&CK mapping."""
    source: str
    service: str = ""
    port: int = 0
    version: str = ""
    attack_tactic: str = "Unknown"
    technique_id: str = "T0000"
    technique_name: str = "Unclassified"
    stride: List[str] = ["Unknown"]
    kill_chain_pos: int = 7
    priority: int = 5
    known_cves: list = []


class PatchOutput(BaseModel):
    """Validated patch generation output."""
    finding_type: str = "unknown"
    file: str = "unknown"
    line: int = 0
    cvss_estimate: float = 0.0
    technique_id: str = ""
    diff: str = ""
    plain_english: str = ""
    confidence: float = 0.0
    bandit_cleared: bool = False
    signature: str = ""
