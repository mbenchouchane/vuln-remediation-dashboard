"""Nessus XML file analyzer using python-libnessus for VulnBot context enrichment."""

import os
import tempfile
from typing import Any, Dict, List, Optional

try:
    from libnessus.parser import NessusParser
    LIBNESSUS_AVAILABLE = True
except ImportError:
    LIBNESSUS_AVAILABLE = False


class NessusXMLAnalyzer:
    """Parse a .nessus XML file and extract structured data for VulnBot."""

    def analyze_file(self, filepath: str) -> Dict[str, Any]:
        """Parse a .nessus file and return structured summary."""
        if not LIBNESSUS_AVAILABLE:
            return {"error": "python-libnessus not installed. Run: pip install python-libnessus"}
        if not os.path.exists(filepath):
            return {"error": f"File not found: {filepath}"}
        try:
            report = NessusParser.parse_fromfile(filepath)
            return self._build_summary(report)
        except Exception as e:
            return {"error": f"Parse error: {str(e)}"}

    def analyze_bytes(self, content: bytes, filename: str = "upload.nessus") -> Dict[str, Any]:
        """Parse .nessus content from bytes (uploaded file)."""
        if not LIBNESSUS_AVAILABLE:
            return {"error": "python-libnessus not installed. Run: pip install python-libnessus"}
        try:
            with tempfile.NamedTemporaryFile(suffix=".nessus", delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            result = self.analyze_file(tmp_path)
            os.unlink(tmp_path)
            return result
        except Exception as e:
            return {"error": f"Temp file error: {str(e)}"}

    def _build_summary(self, report) -> Dict[str, Any]:
        """Build structured summary from a NessusReport object."""
        sev_map = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        all_findings = []

        hosts_summary = []
        for host in report.hosts:
            hosts_summary.append({
                "ip": host.ip,
                "name": host.name,
                "os": host.get_host_properties.get("operating-system", ""),
                "total_vuln": host.get_total_vuln_count,
            })

            for item in host.get_report_items:
                sev_label = self._severity_label(item.severity)
                sev_map[sev_label] = sev_map.get(sev_label, 0) + 1
                all_findings.append({
                    "plugin_id": item.pid,
                    "name": item.plugin_name,
                    "severity": sev_label.capitalize(),
                    "severity_int": item.severity,
                    "host": host.ip,
                    "port": str(item.port),
                    "protocol": item.protocol,
                    "description": (item.description or "")[:300],
                    "solution": (item.solution or "")[:300],
                    "synopsis": (item.synopsis or "")[:200],
                    "cvss_base_score": item.cvss_base_score,
                    "cve": list(item.cve) if item.cve else [],
                })

        # Sort by severity (critical first)
        all_findings.sort(key=lambda f: f["severity_int"], reverse=True)

        return {
            "report_name": report.name,
            "total_hosts": len(report.hosts),
            "total_findings": len(all_findings),
            "severity_counts": sev_map,
            "top_findings": all_findings[:30],
            "hosts": hosts_summary[:20],
        }

    def _severity_label(self, severity_int: int) -> str:
        mapping = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
        return mapping.get(int(severity_int), "info")

    def build_vulnbot_context(self, summary: Dict[str, Any]) -> str:
        """Build a text context string for VulnBot LLM prompt."""
        if "error" in summary:
            return f"Erreur d'analyse du fichier Nessus: {summary['error']}"

        sev = summary.get("severity_counts", {})
        lines = [
            f"=== Rapport Nessus: {summary.get('report_name', 'N/A')} ===",
            f"Hôtes scannés : {summary.get('total_hosts', 0)}",
            f"Total findings : {summary.get('total_findings', 0)}",
            f"  Critical : {sev.get('critical', 0)}",
            f"  High     : {sev.get('high', 0)}",
            f"  Medium   : {sev.get('medium', 0)}",
            f"  Low      : {sev.get('low', 0)}",
            f"  Info     : {sev.get('info', 0)}",
            "",
            "Top vulnérabilités (par sévérité) :",
        ]

        for f in summary.get("top_findings", [])[:15]:
            cve_str = ", ".join(f.get("cve", [])[:3]) if f.get("cve") else ""
            cvss = f"CVSS: {f['cvss_base_score']}" if f.get("cvss_base_score") else ""
            meta = " | ".join(filter(None, [cve_str, cvss]))
            lines.append(
                f"  [{f.get('severity', '?')}] {f.get('name', '?')} "
                f"| {f.get('host', '-')}:{f.get('port', '-')}"
                + (f" | {meta}" if meta else "")
            )
            if f.get("solution"):
                lines.append(f"    → Solution : {f['solution'][:150]}")

        lines.append("")
        lines.append("Hôtes détectés :")
        for h in summary.get("hosts", [])[:10]:
            os_info = f" | OS: {h['os']}" if h.get("os") else ""
            lines.append(f"  {h.get('ip', '?')} ({h.get('name', '')}){os_info} — {h.get('total_vuln', 0)} vulns")

        return "\n".join(lines)


# Singleton
analyzer = NessusXMLAnalyzer()
