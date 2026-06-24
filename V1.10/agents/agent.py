"""OwaspAgent: batched triage with rich output (CVSS, CWE, full analysis)."""
from __future__ import annotations

import json
from typing import Optional

import anthropic

from agents.prompts import PROMPTS
from knowledge import AppKnowledge
from models import (OwaspCategory, RawFinding, Severity, TriagedFinding,
                    ValidationStatus)
from runtime_settings import get_settings

MAX_BATCH_SIZE = 8  # smaller = more tokens per finding = better quality


def _build_client(rt: dict):
    if rt["provider"] == "azure_foundry":
        endpoint = (rt.get("azure_foundry_endpoint") or "").strip().rstrip("/") + "/"
        key = rt.get("azure_foundry_api_key") or ""
        if not endpoint or endpoint == "/":
            raise ValueError("Azure Foundry endpoint not set - add it in Settings.")
        if not key:
            raise ValueError("Azure Foundry API key not set - add it in Settings.")
        from anthropic import AnthropicFoundry
        return AnthropicFoundry(api_key=key, base_url=endpoint)
    return anthropic.Anthropic(api_key=rt["anthropic_api_key"])


def _finding_block(index: int, finding: RawFinding) -> str:
    severity_hint = (finding.raw_severity or "unknown").upper()
    return (
        f"### Finding {index}\n"
        f"Tool: {finding.tool}\n"
        f"ZAP reported severity: {severity_hint}\n"
        f"Title: {finding.title}\n"
        f"URL: {finding.url}\n"
        f"Description: {finding.description}\n"
        f"HTTP evidence:\n{finding.evidence}"
    )


def _safe_severity(val: str) -> Severity:
    try:
        return Severity(val.lower())
    except (ValueError, AttributeError):
        return Severity.LOW


def _safe_vstatus(val: str) -> ValidationStatus:
    try:
        return ValidationStatus(val.lower())
    except (ValueError, AttributeError):
        return ValidationStatus.POTENTIAL


def _safe_float(val) -> Optional[float]:
    try:
        f = float(val)
        return round(f, 1) if f > 0 else None
    except (TypeError, ValueError):
        return None


class OwaspAgent:
    def __init__(self, category: OwaspCategory, knowledge: AppKnowledge | None = None):
        self.category = category
        self.knowledge = knowledge or AppKnowledge()
        self.system_prompt = PROMPTS[category]
        ctx = self.knowledge.for_category(category)
        if ctx:
            self.system_prompt = f"{self.system_prompt}\n\n{ctx}"
        rt = get_settings()
        self.model = rt["agent_model"]
        self.client = _build_client(rt)

    def triage_batch(self, findings: list[RawFinding]) -> tuple[list[TriagedFinding], dict]:
        if not findings:
            return [], {"input_tokens": 0, "output_tokens": 0}

        block = "\n\n".join(_finding_block(i + 1, f) for i, f in enumerate(findings))
        user_msg = (
            f"Analyze these {len(findings)} finding(s) and return a JSON array "
            f"of exactly {len(findings)} objects.\n\n{block}"
        )

        response = self.client.messages.create(
            model=self.model,
            max_tokens=min(500 + 500 * len(findings), 8192),
            system=[{"type": "text", "text": self.system_prompt,
                     "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user_msg}],
        )
        text = "".join(b.text for b in response.content if b.type == "text")

        try:
            parsed_list = json.loads(text)
        except json.JSONDecodeError:
            # attempt to extract JSON array from response
            import re
            m = re.search(r"\[.*\]", text, re.DOTALL)
            parsed_list = json.loads(m.group()) if m else []

        if len(parsed_list) != len(findings):
            raise ValueError(f"Expected {len(findings)} results, got {len(parsed_list)}")

        results: list[TriagedFinding] = []
        for raw, parsed in zip(findings, parsed_list):
            # pull correlation metadata if the engine attached it
            confidence = getattr(raw, "_confidence", 30)
            vstatus_corr = getattr(raw, "_validation_status", ValidationStatus.POTENTIAL)
            source_count = getattr(raw, "_source_count", 1)

            # agent may upgrade validation_status based on evidence
            vstatus_agent = _safe_vstatus(parsed.get("validation_status", "potential"))
            # take the higher of the two
            vstatus_rank = {ValidationStatus.POTENTIAL: 0, ValidationStatus.LIKELY: 1,
                            ValidationStatus.CONFIRMED: 2}
            vstatus = vstatus_corr if vstatus_rank[vstatus_corr] >= vstatus_rank[vstatus_agent] else vstatus_agent

            results.append(TriagedFinding(
                tool=raw.tool,
                category=raw.category,
                app_name=raw.app_name or "unspecified",
                url=raw.url,
                vulnerability_name=parsed.get("vulnerability_name", raw.title),
                severity=_safe_severity(parsed.get("severity", "low")),
                exploitable=bool(parsed.get("exploitable", False)),
                validation_status=vstatus,
                confidence=confidence,
                source_count=source_count,
                cvss_score=_safe_float(parsed.get("cvss_score")),
                cvss_vector=parsed.get("cvss_vector") or None,
                cwe_id=parsed.get("cwe_id", ""),
                cwe_name=parsed.get("cwe_name", ""),
                rationale=parsed.get("rationale", ""),
                root_cause=parsed.get("root_cause"),
                attack_scenario=parsed.get("attack_scenario"),
                technical_impact=parsed.get("technical_impact"),
                business_impact=parsed.get("business_impact"),
                reproduction_steps=parsed.get("reproduction_steps"),
                evidence_summary=parsed.get("evidence_summary"),
                remediation=parsed.get("remediation"),
            ))

        usage = {
            "input_tokens": getattr(response.usage, "input_tokens", 0),
            "output_tokens": getattr(response.usage, "output_tokens", 0),
        }
        return results, usage
