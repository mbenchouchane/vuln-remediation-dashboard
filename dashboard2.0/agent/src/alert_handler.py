"""Alert handler for receiving vulnerability alerts from Nessus and Metasploit."""

from dataclasses import dataclass
from typing import Optional
import requests
from loguru import logger

from config.settings import settings
from src.metasploit_client import MetasploitClient


@dataclass
class VulnerabilityAlert:
    """Represents a vulnerability alert."""

    host: str
    vulnerability_id: str
    severity: str
    description: str
    source: str  # 'nessus', 'metasploit', or 'manual'


class AlertHandler:
    """Handles incoming vulnerability alerts from Nessus and Metasploit."""

    MS17_010_PLUGIN_ID = "97833"  # Nessus plugin ID for MS17-010

    def __init__(self):
        """Initialize the alert handler."""
        self.nessus_host = settings.NESSUS_HOST
        self.nessus_api_key = settings.NESSUS_API_KEY

    def fetch_nessus_alerts(self, scan_id: Optional[str] = None) -> list[VulnerabilityAlert]:
        """Fetch MS17-010 vulnerability alerts from Nessus.

        Args:
            scan_id: Optional specific scan ID to check.

        Returns:
            List of vulnerability alerts from Nessus.
        """
        if not self.nessus_host or not self.nessus_api_key:
            logger.warning("Nessus configuration not set, skipping")
            return []

        alerts = []
        try:
            headers = {"X-ApiKeys": f"accessKey={self.nessus_api_key}"}

            # Get scan results
            endpoint = f"{self.nessus_host}/scans"
            if scan_id:
                endpoint = f"{self.nessus_host}/scans/{scan_id}"

            response = requests.get(endpoint, headers=headers, verify=False, timeout=30)
            response.raise_for_status()

            scan_data = response.json()

            # Look for MS17-010 plugin results
            for host_data in scan_data.get("hosts", []):
                hostname = host_data.get("hostname", "")
                for vuln in host_data.get("vulnerabilities", []):
                    if str(vuln.get("plugin_id")) == self.MS17_010_PLUGIN_ID:
                        alert = VulnerabilityAlert(
                            host=hostname,
                            vulnerability_id="MS17-010",
                            severity=vuln.get("severity_name", "Critical"),
                            description=vuln.get("plugin_name", "MS17-010 EternalBlue"),
                            source="nessus",
                        )
                        alerts.append(alert)

            logger.info(f"Fetched {len(alerts)} alerts from Nessus")
        except requests.RequestException as e:
            logger.error(f"Failed to fetch Nessus alerts: {e}")

        return alerts

    def fetch_metasploit_alerts(self, hosts: Optional[list[str]] = None) -> list[VulnerabilityAlert]:
        """Scan hosts with Metasploit MS17-010 scanner and return alerts for vulnerable ones.

        Args:
            hosts: List of hosts to scan. Defaults to TARGET_HOSTS from settings.

        Returns:
            List of vulnerability alerts for hosts found vulnerable.
        """
        targets = hosts or settings.TARGET_HOSTS
        if not targets:
            logger.warning("No target hosts configured for Metasploit scan")
            return []

        msf = MetasploitClient()
        if not msf.connect():
            logger.error("Could not connect to Metasploit, skipping scan")
            return []

        alerts = []
        scan_results = msf.scan_ms17_010(targets)
        for result in scan_results:
            if result.vulnerable:
                alert = VulnerabilityAlert(
                    host=result.host,
                    vulnerability_id="MS17-010",
                    severity="Critical",
                    description=f"MS17-010 EternalBlue detected by Metasploit: {result.details}",
                    source="metasploit",
                )
                alerts.append(alert)

        logger.info(f"Metasploit scan found {len(alerts)} vulnerable host(s)")
        return alerts

    def get_all_alerts(self) -> list[VulnerabilityAlert]:
        """Fetch alerts from all configured sources.

        Returns:
            Combined list of alerts from Nessus and Metasploit.
        """
        alerts = []
        alerts.extend(self.fetch_nessus_alerts())
        alerts.extend(self.fetch_metasploit_alerts())
        return alerts

    def create_manual_alert(self, host: str) -> VulnerabilityAlert:
        """Create a manual alert for a specific host.

        Args:
            host: Target host IP or hostname.

        Returns:
            A vulnerability alert for the specified host.
        """
        return VulnerabilityAlert(
            host=host,
            vulnerability_id="MS17-010",
            severity="Critical",
            description="Manual remediation request for SMBv1",
            source="manual",
        )
