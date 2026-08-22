from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "harness_generator" / "src" / "langchain_agent"
SRC_DIR = ROOT / "harness_generator" / "src"
for p in (APP_DIR, SRC_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import workflow_graph
from workflow_vuln_scoring import _attack_hint_missing_fields, _vuln_candidates_attack_hint_gaps


def test_build_analysis_evidence_merges_dangerous_sink_rows(tmp_path: Path) -> None:
    src = tmp_path / "decode.c"
    src.write_text(
        "int decode(char *dst, const char *src, int n){\n"
        "    memcpy(dst, src, n);\n"
        "    return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    evidence = workflow_graph._build_analysis_evidence_index(
        repo_root=tmp_path,
        antlr_doc={},
        target_doc={"recommended_targets": []},
        companion_doc={},
    )
    sinks = [
        row
        for row in list(evidence.get("security_evidence") or [])
        if str(row.get("sink") or "") == "memcpy"
    ]
    assert sinks, evidence.get("security_evidence")
    assert int(sinks[0].get("line") or 0) == 2
    assert sinks[0].get("cwe") == "CWE-120"
    assert sinks[0].get("signal_id") == "mem_oob_candidate"
    assert "memcpy" in str(sinks[0].get("summary") or "")


def test_attack_hint_gap_detection() -> None:
    assert _attack_hint_missing_fields({}) == [
        "trigger_condition",
        "key_code_path",
        "boundary_values",
    ]
    assert not _attack_hint_missing_fields(
        {
            "trigger_condition": "len > cap",
            "key_code_path": ["parse", "memcpy"],
            "boundary_values": ["len=0xFFFFFFFF"],
        }
    )
    gaps = _vuln_candidates_attack_hint_gaps(
        [
            {
                "candidate_id": "c1",
                "validation_status": "pending",
                "attack_hint": {"trigger_condition": "TBD"},
            }
        ]
    )
    assert gaps and "c1" in gaps[0]
    assert "boundary_values" in gaps[0]
