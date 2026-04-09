"""Data models for SentinelAgent."""

from enum import Enum
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from datetime import datetime
import uuid


class SecurityLevel(Enum):
    """Security classification levels."""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class RiskLevel(Enum):
    """Risk classification levels for tool calls."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class Document:
    """Represents a document in the retrieval system."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    content: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    embedding: Optional[List[float]] = None
    source: str = ""
    chunk_index: int = 0
    security_level: SecurityLevel = SecurityLevel.BENIGN
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "content": self.content[:200] + "..." if len(self.content) > 200 else self.content,
            "metadata": self.metadata,
            "source": self.source,
            "chunk_index": self.chunk_index,
            "security_level": self.security_level.value
        }


@dataclass
class ToolCall:
    """Represents a proposed tool call."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.LOW
    risk_score: float = 0.0
    allowed: bool = True
    reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "risk_level": self.risk_level.value,
            "risk_score": round(self.risk_score, 3),
            "allowed": self.allowed,
            "reason": self.reason,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class SecurityCheck:
    """Represents a security check result."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    check_type: str = ""  # injection, tool_risk, exfiltration
    passed: bool = True
    confidence: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "check_type": self.check_type,
            "passed": self.passed,
            "confidence": round(self.confidence, 3),
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class TaskResult:
    """Represents the result of a task execution."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    query: str = ""
    status: TaskStatus = TaskStatus.PENDING
    response: str = ""
    steps_taken: int = 0
    tools_used: List[ToolCall] = field(default_factory=list)
    documents_retrieved: List[Document] = field(default_factory=list)
    security_checks: List[SecurityCheck] = field(default_factory=list)
    blocked: bool = False
    block_reason: str = ""
    execution_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    metrics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "query": self.query,
            "status": self.status.value,
            "response": self.response[:500] + "..." if len(self.response) > 500 else self.response,
            "steps_taken": self.steps_taken,
            "tools_used": [t.to_dict() for t in self.tools_used],
            "documents_retrieved": [d.to_dict() for d in self.documents_retrieved],
            "security_checks": [s.to_dict() for s in self.security_checks],
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "execution_time_ms": round(self.execution_time_ms, 2),
            "timestamp": self.timestamp.isoformat(),
            "metrics": self.metrics
        }


@dataclass
class AttackResult:
    """Represents the result of an attack simulation."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    attack_type: str = ""  # injection, exfiltration, tool_misuse
    payload: str = ""
    success: bool = False
    defense_triggered: bool = False
    leaked_secrets: List[str] = field(default_factory=list)
    unsafe_tools_called: List[str] = field(default_factory=list)
    response: str = ""
    defense_config: str = ""  # no-defense, prompt-only, rule-based, ml-assisted
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "attack_type": self.attack_type,
            "payload": self.payload[:200] + "..." if len(self.payload) > 200 else self.payload,
            "success": self.success,
            "defense_triggered": self.defense_triggered,
            "leaked_secrets": self.leaked_secrets,
            "unsafe_tools_called": self.unsafe_tools_called,
            "response": self.response[:300] + "..." if len(self.response) > 300 else self.response,
            "defense_config": self.defense_config,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class MetricsSummary:
    """Summary of evaluation metrics."""
    total_tasks: int = 0
    successful_tasks: int = 0
    blocked_attacks: int = 0
    total_attacks: int = 0
    attack_success_rate: float = 0.0
    leakage_rate: float = 0.0
    unsafe_tool_rate: float = 0.0
    benign_task_success_rate: float = 0.0
    avg_latency_ms: float = 0.0
    injection_detection_accuracy: float = 0.0
    tool_risk_accuracy: float = 0.0
    false_positive_rate: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_tasks": self.total_tasks,
            "successful_tasks": self.successful_tasks,
            "blocked_attacks": self.blocked_attacks,
            "total_attacks": self.total_attacks,
            "attack_success_rate": round(self.attack_success_rate, 3),
            "leakage_rate": round(self.leakage_rate, 3),
            "unsafe_tool_rate": round(self.unsafe_tool_rate, 3),
            "benign_task_success_rate": round(self.benign_task_success_rate, 3),
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "injection_detection_accuracy": round(self.injection_detection_accuracy, 3),
            "tool_risk_accuracy": round(self.tool_risk_accuracy, 3),
            "false_positive_rate": round(self.false_positive_rate, 3),
            "timestamp": self.timestamp.isoformat()
        }


# API Request/Response Models
@dataclass
class QueryRequest:
    """Request model for agent queries."""
    query: str
    context: Optional[Dict[str, Any]] = None
    enable_defense: bool = True


@dataclass
class QueryResponse:
    """Response model for agent queries."""
    result: TaskResult
    message: str = ""


@dataclass
class AttackSimulationRequest:
    """Request model for attack simulation."""
    attack_type: str
    payload: str
    defense_config: str = "ml-assisted"


@dataclass
class AttackSimulationResponse:
    """Response model for attack simulation."""
    result: AttackResult
    comparison: Dict[str, Any] = field(default_factory=dict)
