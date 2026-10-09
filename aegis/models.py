from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Location:
    path: str
    line: int

    def to_dict(self) -> dict:
        return {"path": self.path, "line": self.line}


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    asset: str
    recommendation: str
    locations: tuple[Location, ...]
    status: str = "open"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "asset": self.asset,
            "recommendation": self.recommendation,
            "status": self.status,
            "locations": [loc.to_dict() for loc in self.locations],
        }
