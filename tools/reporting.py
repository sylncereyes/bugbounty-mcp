import os
import csv
from mcp_instance import mcp
from tools.db import get_findings, get_target, get_finding_stats
from jinja2 import Environment, FileSystemLoader, select_autoescape
from datetime import datetime
from pathlib import Path

_PROJECT_ROOT = Path(__file__).parent.parent
_TEMPLATE_DIR = _PROJECT_ROOT / "templates"
_DEFAULT_REPORTS_DIR = _PROJECT_ROOT / os.getenv("REPORTS_DIR", "reports")


def _safe_output_path(output_path: str, default_name: str) -> str:
    """Validate and resolve output path, ensuring it stays within the reports directory."""
    reports_dir = _DEFAULT_REPORTS_DIR
    reports_dir.mkdir(parents=True, exist_ok=True)

    if not output_path:
        return str(reports_dir / default_name)

    resolved = Path(output_path).resolve()
    # Allow writing only inside the reports directory
    if not resolved.is_relative_to(reports_dir.resolve()):
        # Fall back to reports dir with the filename only
        return str(reports_dir / resolved.name)
    return str(resolved)


@mcp.tool()
def generate_report(target_id: int, report_format: str = "html", output_path: str = None) -> dict:
    """Generates vulnerability assessment report in HTML or Markdown format."""
    target = get_target(target_id)
    if not target:
        return {"error": f"Target ID {target_id} not found."}

    findings = get_findings(target_id)
    stats = get_finding_stats(target_id)

    ext = "html" if report_format.lower() == "html" else "md"
    output_path = _safe_output_path(output_path, f"target_{target_id}_report.{ext}")

    if report_format.lower() == "html":
        # Read HTML template with autoescape enabled to prevent XSS
        try:
            env = Environment(
                loader=FileSystemLoader(str(_TEMPLATE_DIR)),
                autoescape=select_autoescape(["html", "htm"])
            )
            t = env.get_template("report.html")
        except Exception:
            # Simple fallback HTML with manual autoescaping
            from markupsafe import escape
            fallback = "<html><head><title>Vulnerability Report</title></head><body>"
            fallback += f"<h1>Report for {escape(target.get('program_name', 'Unknown'))}</h1>"
            fallback += f"<p>Domain: {escape(target.get('domain', 'Unknown'))}</p>"
            fallback += f"<h2>Stats: {escape(str(stats))}</h2>"
            fallback += "<h2>Findings</h2><ul>"
            for f_item in findings:
                fallback += f"<li><strong>{escape(f_item.get('title', ''))}</strong> - {escape(f_item.get('severity', ''))} - {escape(f_item.get('owasp_category', ''))}</li>"
            fallback += "</ul></body></html>"
            with open(output_path, "w") as f:
                f.write(fallback)
            return {
                "status": "success",
                "output_path": output_path,
                "format": report_format,
                "findings_count": len(findings)
            }

        # Build OWASP category stats for the template
        owasp_stats = {}
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
        for f_item in findings:
            cat = f_item.get("owasp_category", "Unknown")
            sev = f_item.get("severity", "Informational")
            if cat not in owasp_stats:
                owasp_stats[cat] = {"count": 0, "max_severity": sev}
            owasp_stats[cat]["count"] += 1
            if severity_order.get(sev, 99) < severity_order.get(owasp_stats[cat]["max_severity"], 99):
                owasp_stats[cat]["max_severity"] = sev

        rendered = t.render(
            target=target,
            findings=findings,
            stats=stats,
            report_date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            owasp_stats=owasp_stats
        )

        with open(output_path, "w") as f:
            f.write(rendered)
    else:
        # Generate simple Markdown report
        markdown = f"""# Bug Bounty Vulnerability Assessment Report

## 🎯 Target Information
* **Program Name**: {target.get('program_name')}
* **Domain**: {target.get('domain')}
* **Scope**: {target.get('scope')}
* **Bounty Range**: {target.get('bounty_range')}

## 📊 Findings Summary
* **Critical**: {stats.get('Critical', 0)}
* **High**: {stats.get('High', 0)}
* **Medium**: {stats.get('Medium', 0)}
* **Low**: {stats.get('Low', 0)}
* **Informational**: {stats.get('Informational', 0)}
* **Total**: {stats.get('total', 0)}

## 🐛 Detailed Findings
"""
        for idx, f_item in enumerate(findings):
            markdown += f"""
### {idx+1}. {f_item.get('title')}
* **Severity**: {f_item.get('severity')}
* **OWASP Category**: {f_item.get('owasp_category')}
* **Vulnerability Type**: {f_item.get('vulnerability_type')}
* **URL**: {f_item.get('url')}
* **Parameter**: {f_item.get('parameter')}
* **Description**: {f_item.get('description')}
* **Evidence**: {f_item.get('evidence')}
"""
        with open(output_path, "w") as out_f:
            out_f.write(markdown)

    return {
        "status": "success",
        "output_path": output_path,
        "format": report_format,
        "findings_count": len(findings)
    }

@mcp.tool()
def generate_executive_summary(target_id: int) -> str:
    """Generates an executive summary of target security posture."""
    stats = get_finding_stats(target_id)
    target = get_target(target_id)

    if not target:
        return "Target not found."

    summary = f"Executive security summary for {target.get('program_name')} ({target.get('domain')}).\n"
    summary += f"Total vulnerabilities detected: {stats.get('total', 0)}.\n"
    summary += f"- Critical: {stats.get('Critical', 0)}\n"
    summary += f"- High: {stats.get('High', 0)}\n"
    summary += f"- Medium: {stats.get('Medium', 0)}\n"
    summary += f"- Low: {stats.get('Low', 0)}\n"

    if stats.get('Critical', 0) > 0 or stats.get('High', 0) > 0:
        summary += "\nAction Required: Immediate patching or compensating controls are advised to mitigate high severity risks."
    else:
        summary += "\nOverall Status: Relatively secure baseline. Periodic automated scans are recommended."

    return summary

@mcp.tool()
def export_findings_csv(target_id: int, output_path: str = None) -> dict:
    """Exports target findings to CSV format."""
    findings = get_findings(target_id)

    if not findings:
        return {"error": "No findings to export."}

    output_path = _safe_output_path(output_path, f"target_{target_id}_findings.csv")

    keys = findings[0].keys()
    with open(output_path, "w", newline="") as f:
        dict_writer = csv.DictWriter(f, keys)
        dict_writer.writeheader()
        dict_writer.writerows(findings)

    return {"status": "success", "output_path": output_path, "count": len(findings)}
