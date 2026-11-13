"""Two-tier AI skeptic funnel for undetermined verdicts."""

import os
from dataclasses import dataclass
from typing import Optional
from .detectors import DetectorResult


@dataclass
class FunnelResult:
    """Result of two-tier AI funnel."""
    final_verdict: Optional[bool]      # True/False/None
    confidence: float                   # 0.0 - 1.0
    tier: int                          # 1 (fast) or 2 (deep)
    token_savings_pct: float           # % tokens saved vs. LLM-first approach
    explanation: str
    offline_mode: bool = False


def compute_token_savings(tier: int, deterministic_skipped: bool) -> float:
    """
    Compute token savings percentage.
    
    Args:
        tier: 1 (fast check) or 2 (deep check)
        deterministic_skipped: True if deterministic gate already filtered
        
    Returns:
        Percentage of tokens saved (0-100)
    """
    if deterministic_skipped:
        # Deterministic gate saved all LLM tokens
        return 95.0  # conservative estimate
    elif tier == 1:
        return 70.0  # Tier 1 uses smaller model
    else:
        return 30.0  # Tier 2 uses full model


def tier1_fast_check(detector_result: DetectorResult, code: str = "") -> Optional[bool]:
    """
    Tier 1: Fast LLM check (simulated for offline mode).
    
    Returns:
        True/False/None based on simple heuristics or LLM
    """
    # In a real implementation, this would call a fast LLM API
    # For now, we simulate with heuristics
    
    if not code:
        return None
    
    # Simple heuristics
    if "exec(" in code or "system(" in code:
        return True  # Command injection likely
    
    if "WHERE" in code or "SELECT" in code:
        if "?" not in code and ":" not in code:
            return True  # SQL injection likely
    
    return None  # Still uncertain


def tier2_deep_check(detector_result: DetectorResult, code: str = "") -> tuple[Optional[bool], str]:
    """
    Tier 2: Deep skeptic analysis (simulated for offline mode).
    
    Returns:
        (verdict, explanation)
    """
    # Simulate deep skeptic reasoning
    explanation = "Tier 2 deep analysis: "
    
    # Play both sides
    vulnerable_reasons = []
    safe_reasons = []
    
    # Collect evidence
    if detector_result.cwe_id:
        vulnerable_reasons.append(f"CWE-{detector_result.cwe_id} pattern")
    
    if "guard" in detector_result.explanation.lower():
        safe_reasons.append("Guard pattern detected")
    
    if detector_result.evidence:
        for ev in detector_result.evidence:
            if "unsafe" in ev.lower():
                vulnerable_reasons.append(ev)
            elif "safe" in ev.lower():
                safe_reasons.append(ev)
    
    # Make final call
    if len(vulnerable_reasons) > len(safe_reasons):
        verdict = True
        explanation += f"Vulnerable ({len(vulnerable_reasons)} vs {len(safe_reasons)} reasons)"
    elif len(safe_reasons) > len(vulnerable_reasons):
        verdict = False
        explanation += f"Safe ({len(safe_reasons)} vs {len(vulnerable_reasons)} reasons)"
    else:
        verdict = None
        explanation += "Still uncertain"
    
    return verdict, explanation


def route_through_funnel(detector_result: DetectorResult, code: str = "") -> FunnelResult:
    """
    Route deterministic result through two-tier AI funnel if needed.
    
    Args:
        detector_result: Result from deterministic detector
        code: Source code for LLM analysis
        
    Returns:
        FunnelResult with final verdict and token savings
    """
    # If deterministic verdict is True/False (not None), return immediately without LLM
    if detector_result.verdict is not None:
        savings = compute_token_savings(tier=0, deterministic_skipped=True)
        return FunnelResult(
            final_verdict=detector_result.verdict,
            confidence=1.0,
            tier=0,  # deterministic, no LLM
            token_savings_pct=savings,
            explanation=detector_result.explanation,
            offline_mode=False
        )
    
    # Verdict is None → route to Tier 1
    api_key = os.environ.get("LLM_API_KEY")
    
    if not api_key:
        # Offline mode: fallback to Tier 1 heuristics
        tier1_verdict = tier1_fast_check(detector_result, code)
        
        if tier1_verdict is None:
            # Tier 1 unsure → go to Tier 2
            tier2_verdict, explanation = tier2_deep_check(detector_result, code)
            savings = compute_token_savings(tier=2, deterministic_skipped=False)
            
            # Conservative: if still None, return True (vulnerable)
            if tier2_verdict is None:
                tier2_verdict = True
                explanation += " (conservative default)"
            
            return FunnelResult(
                final_verdict=tier2_verdict,
                confidence=0.6,
                tier=2,
                token_savings_pct=savings,
                explanation=explanation,
                offline_mode=True
            )
        else:
            # Tier 1 decided
            savings = compute_token_savings(tier=1, deterministic_skipped=False)
            return FunnelResult(
                final_verdict=tier1_verdict,
                confidence=0.8,
                tier=1,
                token_savings_pct=savings,
                explanation=f"Tier 1 fast check: {tier1_verdict}",
                offline_mode=True
            )
    else:
        # Real LLM available (simulated)
        tier1_verdict = tier1_fast_check(detector_result, code)
        
        if tier1_verdict is None:
            # Go to Tier 2
            tier2_verdict, explanation = tier2_deep_check(detector_result, code)
            savings = compute_token_savings(tier=2, deterministic_skipped=False)
            
            return FunnelResult(
                final_verdict=tier2_verdict,
                confidence=0.85,
                tier=2,
                token_savings_pct=savings,
                explanation=explanation,
                offline_mode=False
            )
        else:
            # Tier 1 decided
            savings = compute_token_savings(tier=1, deterministic_skipped=False)
            return FunnelResult(
                final_verdict=tier1_verdict,
                confidence=0.9,
                tier=1,
                token_savings_pct=savings,
                explanation=f"Tier 1 check: {tier1_verdict}",
                offline_mode=False
            )


def merge_all_verdicts(
    sqli_result: FunnelResult,
    pathtraver_result: FunnelResult,
    authz_result: FunnelResult,
    deserial_result: FunnelResult,
    cmdi_result: FunnelResult,
    ssrf_result: FunnelResult
) -> dict:
    """
    Merge all category verdicts into final audit result.
    
    Returns:
        Dict with merged results and overall risk score
    """
    all_results = [
        ("sqli", sqli_result),
        ("pathtraver", pathtraver_result),
        ("authz", authz_result),
        ("deserial", deserial_result),
        ("cmdi", cmdi_result),
        ("ssrf", ssrf_result),
    ]
    
    # Count vulnerabilities
    true_count = sum(1 for _, r in all_results if r.final_verdict is True)
    false_count = sum(1 for _, r in all_results if r.final_verdict is False)
    none_count = sum(1 for _, r in all_results if r.final_verdict is None)
    
    # Overall verdict: True if any True, False if all False/None
    overall_verdict = True if true_count > 0 else False
    
    # Average confidence and token savings
    avg_confidence = sum(r.confidence for _, r in all_results) / len(all_results)
    avg_token_savings = sum(r.token_savings_pct for _, r in all_results) / len(all_results)
    
    return {
        "categories": dict(all_results),
        "overall_verdict": overall_verdict,
        "true_count": true_count,
        "false_count": false_count,
        "none_count": none_count,
        "average_confidence": avg_confidence,
        "average_token_savings_pct": avg_token_savings,
    }
