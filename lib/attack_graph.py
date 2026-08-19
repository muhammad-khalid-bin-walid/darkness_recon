"""
lib/attack_graph.py — Graph-based attack-path data layer (plan Phase 29)
Builds exploitable attack paths from correlation data.
Output: output/<target>/attack_paths.json
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

# Severity numeric weights for path scoring
_SEV_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}


class AttackGraph:
    """
    Directed graph of attack paths.
    Nodes: assets and findings.
    Edges: exploitation relationships (finding → asset pivot, finding chained to finding).
    """

    def __init__(self):
        self._nodes: dict[str, dict] = {}       # id -> {type, label, severity, ...}
        self._edges: list[dict] = []             # [{src, dst, label, weight}]

    def add_asset_node(self, asset_id: str, domain: str, criticality: str = "prod") -> None:
        self._nodes[asset_id] = {"id": asset_id, "type": "asset", "label": domain, "criticality": criticality}

    def add_finding_node(self, finding_id: str, title: str, severity: str, confidence: float = 0.0) -> None:
        self._nodes[finding_id] = {
            "id": finding_id, "type": "finding", "label": title,
            "severity": severity, "confidence": confidence,
        }

    def add_edge(self, src: str, dst: str, label: str = "", weight: float = 1.0) -> None:
        self._edges.append({"src": src, "dst": dst, "label": label, "weight": round(weight, 3)})

    def get_attack_paths(self, max_depth: int = 5) -> list[dict]:
        """
        Enumerate attack paths from entry-point findings to high-value assets.
        Uses DFS with depth limit.
        """
        # Build adjacency map
        adj: dict[str, list[str]] = defaultdict(list)
        for edge in self._edges:
            adj[edge["src"]].append(edge["dst"])

        # Entry points: high/critical findings
        entry_points = [
            nid for nid, node in self._nodes.items()
            if node.get("type") == "finding"
            and node.get("severity") in ("critical", "high")
        ]

        # Target nodes: prod assets
        targets = {
            nid for nid, node in self._nodes.items()
            if node.get("type") == "asset" and node.get("criticality") == "prod"
        }

        paths: list[dict] = []
        for start in entry_points:
            stack = [(start, [start])]
            while stack:
                node, path = stack.pop()
                if node in targets and len(path) > 1:
                    score = self._path_score(path)
                    paths.append({"path": path, "length": len(path), "score": score,
                                  "nodes": [self._nodes.get(n, {"id": n}) for n in path]})
                if len(path) < max_depth:
                    for neighbor in adj.get(node, []):
                        if neighbor not in path:
                            stack.append((neighbor, path + [neighbor]))
        paths.sort(key=lambda p: p["score"], reverse=True)
        return paths

    def _path_score(self, path: list[str]) -> float:
        score = 0.0
        for nid in path:
            node = self._nodes.get(nid, {})
            sev = node.get("severity", "info")
            score += _SEV_WEIGHTS.get(sev, 0)
            score += node.get("confidence", 0.0) * 2
        return round(score, 2)

    def to_dict(self) -> dict:
        return {"nodes": list(self._nodes.values()), "edges": self._edges}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, target: str, output_dir: str = "output") -> None:
        p = Path(output_dir) / target / "attack_paths.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {"graph": self.to_dict(), "attack_paths": self.get_attack_paths()}
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")


def build_from_correlation(assets: list[dict], findings: list[dict]) -> AttackGraph:
    """Build an AttackGraph from asset and finding lists."""
    g = AttackGraph()
    for a in assets:
        g.add_asset_node(a.get("id", ""), a.get("domain", ""), a.get("criticality", "prod"))
    for f in findings:
        g.add_finding_node(f.get("id", ""), f.get("title", ""), f.get("severity", "info"), f.get("confidence", 0.0))
        # Link finding to its asset
        g.add_edge(f.get("id", ""), f.get("asset_id", ""), label="affects",
                   weight=_SEV_WEIGHTS.get(f.get("severity", "info"), 0))
    return g
