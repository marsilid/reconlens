"""Data model shared by modules, the scanner and the reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any

from reconlens.scoring import compute_score, grade_for


@dataclass(slots=True)
class LookupSection:
    """One block in a lookup report: either a key/value ``data`` map or table ``rows``."""

    title: str
    data: dict[str, Any] | None = None
    rows: list[dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"title": self.title}
        if self.rows is not None:
            out["rows"] = self.rows
        if self.data is not None:
            out["data"] = self.data
        return out


@dataclass(slots=True)
class LookupReport:
    """Result of a non-domain lookup (phone, username, e-mail).

    Deliberately has no security score: these lookups describe a target, they do
    not grade it. The HTML/JSON writers render it generically.
    """

    kind: str
    target: str
    summary: dict[str, Any] = field(default_factory=dict)
    sections: list[LookupSection] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    disclaimer: str = ""
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_context(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target,
            "summary": self.summary,
            "sections": [s.to_dict() for s in self.sections],
            "notes": self.notes,
            "disclaimer": self.disclaimer,
            "generated_at": self.generated_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target,
            "generated_at": self.generated_at.isoformat(),
            "summary": self.summary,
            "sections": [s.to_dict() for s in self.sections],
            "notes": self.notes,
        }


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(slots=True)
class Finding:
    """A single observation worth the reader's attention."""

    title: str
    severity: Severity
    description: str = ""
    recommendation: str = ""
    module: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.label,
            "description": self.description,
            "recommendation": self.recommendation,
            "module": self.module,
        }


@dataclass(slots=True)
class ModuleResult:
    """Output of one module: raw collected data plus the findings derived from it."""

    name: str
    title: str
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "data": self.data,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "duration": round(self.duration, 3),
        }


@dataclass(slots=True)
class ScanReport:
    target: str
    started_at: datetime
    finished_at: datetime | None = None
    results: list[ModuleResult] = field(default_factory=list)
    dns_backend: str = "system"
    notes: list[str] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        """All findings, most severe first."""
        items = [f for r in self.results for f in r.findings]
        return sorted(items, key=lambda f: f.severity, reverse=True)

    @property
    def score(self) -> int:
        return compute_score(f.severity for f in self.findings)

    @property
    def grade(self) -> str:
        return grade_for(self.score)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            counts[f.severity.label] += 1
        return counts

    @property
    def duration(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "score": self.score,
            "grade": self.grade,
            "dns_backend": self.dns_backend,
            "notes": self.notes,
            "severity_counts": self.severity_counts,
            "findings": [f.to_dict() for f in self.findings],
            "modules": [r.to_dict() for r in self.results],
        }
