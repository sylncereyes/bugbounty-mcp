"""Impact Scoring & Panic Factor Module"""
import logging
from mcp_instance import mcp

logger = logging.getLogger("stealthvision")

PANIC_FACTORS = {
    "rce": {"score": 100, "panic": "CRITICAL", "business_impact": "Full system compromise, complete data breach risk"},
    "auth_bypass": {"score": 95, "panic": "HIGH", "business_impact": "Unauthorized access to all user accounts and admin panels"},
    "data_exposure": {"score": 90, "panic": "HIGH", "business_impact": "Customer PII/PHI/PCI exposure - regulatory fines"},
    "payment_bypass": {"score": 98, "panic": "CRITICAL", "business_impact": "Direct revenue loss, fraud detection bypass"},
    "admin_takeover": {"score": 95, "panic": "HIGH", "business_impact": "Full platform control, user data manipulation"},
    "mass_assignment": {"score": 85, "panic": "MEDIUM", "business_impact": "Privilege escalation at scale"},
}

@mcp.tool()
def calculate_impact(vulnerability_type: str, asset_type: str = "user_data", 
                     exposed_records: int = 0, auth_bypass: bool = False) -> dict:
    """Calculate business impact score and panic factor."""
    base = PANIC_FACTORS.get(vulnerability_type.lower(), {"score": 50, "panic": "LOW", "business_impact": "Limited impact"})
    
    # Adjust for scale
    if exposed_records > 0:
        if exposed_records > 1_000_000:
            base["score"] = min(100, base["score"] + 10)
            base["panic"] = "CRITICAL"
        elif exposed_records > 100_000:
            base["score"] = min(100, base["score"] + 5)
    
    return {
        "vulnerability": vulnerability_type,
        "impact_score": base["score"],
        "panic_factor": base["panic"],
        "business_impact": base["business_impact"],
        "estimated_records": exposed_records,
        "recommendation": f"Immediate patch required - {base['panic']} priority vulnerability detected"
    }

@mcp.tool()
def suggest_impact_narrative(vuln_type: str, target_asset: str) -> dict:
    """Generate panic-inducing narrative for triage."""
    narratives = {
        "auth_bypass": f"CRITICAL: {target_asset} authentication completely bypassed. Attackers can impersonate ANY user without credentials. Immediate security incident.",
        "rce": f"CRITICAL: Remote Code Execution on {target_asset}. Full server control achieved. Data exfiltration and lateral movement possible.",
        "payment_bypass": f"CRITICAL: Payment processing on {target_asset} can be fully bypassed. Direct revenue theft vector. Fraud alerts ignored.",
        "data_exposure": f"HIGH: {target_asset} exposing sensitive customer data. GDPR/HIPAA/PCI-DSS compliance violation imminent.",
    }
    return {"narrative": narratives.get(vuln_type.lower(), "Vulnerability detected - review required")}

@mcp.tool()
def crown_jewel_prioritize(domain: str, assets: list = None) -> dict:
    """Prioritize crown jewel assets for maximum panic factor."""
    jewel_assets = ["auth", "payment", "admin", "api", "user", "customer", "billing"]
    if assets is None:
        assets = jewel_assets
    else:
        assets = list(assets)
    
    prioritized = []
    for jewel in jewel_assets:
        score = 100 - (jewel_assets.index(jewel) * 15)
        prioritized.append({"asset": jewel, "priority_score": score, "focus_area": f"{domain}/{jewel}"})
    
    return {"prioritized_assets": prioritized, "strategy": "Focus on auth/payment first for maximum impact"}