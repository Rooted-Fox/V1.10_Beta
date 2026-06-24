"""Approval-gated AI triage: correlation → batched agent triage → attack chains."""
from __future__ import annotations

from collections import defaultdict
from typing import Optional

from agents.agent import MAX_BATCH_SIZE, OwaspAgent
from attack_chain_engine import detect_chains
from correlation_engine import correlate
from models import RemediationStatus, TriagedFinding, ValidationStatus
from notifier import notify_new_critical_findings
from pending_store import PendingFindingsStore
from runtime_settings import get_settings
from store import FindingsStore
from token_store import TokenStore


class TokenBudgetExceeded(RuntimeError):
    pass


class AIIntegrationDisabled(RuntimeError):
    pass


def triage_app(app_name: Optional[str], token_limit: Optional[int]) -> dict:
    if not get_settings()["ai_enabled"]:
        raise AIIntegrationDisabled(
            "Opus/AI integration is off. Enable it on the Settings tab before approving triage."
        )

    pending_store = PendingFindingsStore()
    token_store = TokenStore()
    store = FindingsStore()

    if not token_store.has_budget(token_limit):
        raise TokenBudgetExceeded(
            f"Token budget ({token_limit}) already reached. Raise the limit or reset in Settings."
        )

    raw_findings = pending_store.take_for_triage(app_name=app_name)

    # --- Correlation: dedup and assign confidence before sending to agents ---
    correlated = correlate(raw_findings)

    by_category = defaultdict(list)
    for finding in correlated:
        by_category[finding.category].append(finding)

    triaged: list[TriagedFinding] = []
    stopped_early = False

    for category, findings in by_category.items():
        if stopped_early:
            break
        agent = OwaspAgent(category)
        for i in range(0, len(findings), MAX_BATCH_SIZE):
            if not token_store.has_budget(token_limit):
                stopped_early = True
                break
            chunk = findings[i: i + MAX_BATCH_SIZE]
            results, usage = agent.triage_batch(chunk)
            token_store.record(category.value, usage["input_tokens"], usage["output_tokens"])
            for result in results:
                finding_id = store.save(result)
                result.id = finding_id
                triaged.append(result)
        if stopped_early:
            break

    # --- Attack chain detection (runs after all findings are stored) ---
    chain_count = 0
    if triaged and not stopped_early and get_settings()["ai_enabled"]:
        target_app = app_name or (triaged[0].app_name if triaged else "unspecified")
        store.delete_chains_for_app(target_app)
        chains = detect_chains(triaged, target_app)
        for chain in chains:
            store.save_chain(chain)
        chain_count = len(chains)

    notify_new_critical_findings(triaged)

    return {
        "triaged_count": len(triaged),
        "correlated_from": len(raw_findings),
        "dedup_removed": len(raw_findings) - len(correlated),
        "chain_count": chain_count,
        "remaining_pending": len(pending_store.pending(app_name=app_name)),
        "stopped_early": stopped_early,
        "tokens_used_total": token_store.total_used(),
    }
